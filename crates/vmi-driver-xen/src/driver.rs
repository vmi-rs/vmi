use std::{
    cell::RefCell,
    collections::HashMap,
    os::fd::AsRawFd as _,
    time::{Duration, Instant},
};

use vmi_core::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiEvent, VmiEventResponse,
    VmiInfo, VmiMappedPage,
};
use xen::{
    ctrl::VmEventRing, XenAltP2M, XenAltP2MView, XenControl, XenDeviceModel, XenDomain,
    XenDomainId, XenDomainInfo, XenEventChannelPort, XenForeignMemory, XenForeignMemoryProtection,
    XenMonitor,
};

use crate::{ArchAdapter, Error, IntoExt as _};

/// VMI driver for Xen hypervisor.
pub struct XenDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub(crate) domain: XenDomain<Arch::XenArch>,
    pub(crate) devicemodel: XenDeviceModel,
    pub(crate) monitor: XenMonitor,
    pub(crate) altp2m: XenAltP2M,
    pub(crate) evtchn: XenEventChannelPort,
    pub(crate) foreign_memory: XenForeignMemory,
    pub(crate) info: XenDomainInfo,

    pub(crate) ring: RefCell<VmEventRing>,
    pub(crate) views: RefCell<HashMap<u16, XenAltP2MView>>,
    pub(crate) event_processing_overhead: RefCell<Duration>,
}

impl<Arch> Drop for XenDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    fn drop(&mut self) {
        let max_memkb = self.info.max_pages * Arch::PAGE_SIZE / 1024;

        let _ = self.domain.set_max_mem(max_memkb);
        let _ = self.monitor.emul_unimplemented(false);
        let _ = self.monitor.inguest_pagefault(false);
    }
}

impl<Arch> XenDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    pub fn new(domain_id: XenDomainId) -> Result<Self, Error> {
        let xc = XenControl::new()?;
        let domain = xc.domain(domain_id)?;
        domain.set_max_mem(u64::MAX)?;

        let devicemodel = domain.device_model()?;
        let (monitor, ring) = domain.monitor()?;
        let altp2m = domain.altp2m()?;
        let evtchn = monitor.channel()?;
        let foreign_memory = XenForeignMemory::new()?;
        let info = domain.info()?;

        monitor.inguest_pagefault(true)?;
        monitor.emul_unimplemented(true)?;

        Ok(Self {
            domain,
            devicemodel,
            monitor,
            altp2m,
            evtchn,
            foreign_memory,
            info,
            ring: RefCell::new(ring),
            views: RefCell::new(HashMap::new()),
            event_processing_overhead: RefCell::new(Duration::from_millis(0)),
        })
    }

    pub fn info(&self) -> Result<VmiInfo, Error> {
        Ok(VmiInfo {
            page_size: Arch::PAGE_SIZE,
            page_shift: Arch::PAGE_SHIFT,
            max_gfn: Gfn::new(self.domain.maximum_gpfn()?),
            vcpus: self.info.max_vcpu_id + 1,
        })
    }

    pub fn pause(&self) -> Result<(), Error> {
        Ok(self.domain.pause()?)
    }

    pub fn resume(&self) -> Result<(), Error> {
        Ok(self.domain.unpause()?)
    }

    pub fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, Error> {
        Arch::registers(self, vcpu)
    }

    pub fn set_registers(&self, vcpu: VcpuId, registers: Arch::Registers) -> Result<(), Error> {
        Arch::set_registers(self, vcpu, registers)
    }

    pub fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, Error> {
        if view.0 == 0 {
            return Ok(self.domain.get_mem_access(gfn.0)?.into_ext());
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => Ok(view.get_mem_access(gfn.0)?.into_ext()),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), Error> {
        tracing::trace!(%gfn, %view, %access, "set memory access");

        if view.0 == 0 {
            return Ok(self.domain.set_mem_access(gfn.into(), access.into_ext())?);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => Ok(view.set_mem_access(gfn.into(), access.into_ext())?),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), Error> {
        tracing::trace!(%gfn, %view, %access, "set memory access");

        let mut xen_access = access.into_ext();

        if options.contains(MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES) {
            if access != MemoryAccess::R {
                return Err(Error::NotSupported);
            }

            xen_access = xen::MemoryAccess::R2PW;
        }

        if view.0 == 0 {
            return Ok(self.domain.set_mem_access(gfn.into(), xen_access)?);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => Ok(view.set_mem_access(gfn.into(), xen_access)?),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, Error> {
        let page = self.foreign_memory.map(
            self.domain.id(),
            XenForeignMemoryProtection::READ,
            &[u64::from(gfn)],
            None,
        )?;

        Ok(VmiMappedPage::new(page))
    }

    pub fn write_page(
        &self,
        gfn: Gfn,
        offset: u64,
        content: &[u8],
    ) -> Result<VmiMappedPage, Error> {
        let mut page = self.foreign_memory.map(
            self.domain.id(),
            XenForeignMemoryProtection::WRITE,
            &[u64::from(gfn)],
            None,
        )?;

        let offset = offset as usize;
        if offset + content.len() > Arch::PAGE_SIZE as usize {
            return Err(Error::OutOfBounds);
        }

        page[offset..offset + content.len()].copy_from_slice(content);

        Ok(VmiMappedPage::new(page))
    }

    pub fn allocate_gfn(&self, gfn: Gfn) -> Result<(), Error> {
        Ok(self.domain.populate_physmap_exact(0, 0, &[gfn.into()])?)
    }

    pub fn free_gfn(&self, gfn: Gfn) -> Result<(), Error> {
        Ok(self.domain.decrease_reservation_exact(0, &[gfn.into()])?)
    }

    pub fn default_view(&self) -> View {
        View(0)
    }

    pub fn create_view(&self, default_access: MemoryAccess) -> Result<View, Error> {
        let view = self.altp2m.create_view(default_access.into_ext())?;

        let id = view.id();
        self.views.borrow_mut().insert(id, view);

        Ok(View(id))
    }

    pub fn destroy_view(&self, view: View) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow_mut().remove(&view.0) {
            // View is destroyed automatically when it goes out of scope
            Some(_view) => Ok(()),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn switch_to_view(&self, view: View) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(self.altp2m.reset_view()?);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => Ok(view.switch()?),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow().get(&view.0) {
            // WARNING: This will change access permissions of the GFN!
            Some(view) => Ok(view.change_gfn(old_gfn.into(), new_gfn.into())?),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow().get(&view.0) {
            // WARNING: This will change access permissions of the GFN!
            Some(view) => Ok(view.change_gfn(gfn.into(), u64::MAX)?),
            None => Err(Error::ViewNotFound),
        }
    }

    pub fn monitor_enable(&self, option: Arch::EventMonitor) -> Result<(), Error> {
        Arch::monitor_enable(self, option)
    }

    pub fn monitor_disable(&self, option: Arch::EventMonitor) -> Result<(), Error> {
        Arch::monitor_disable(self, option)
    }

    pub fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), Error> {
        Arch::inject_interrupt(self, vcpu, interrupt)
    }

    pub fn events_pending(&self) -> usize {
        self.ring.borrow().unconsumed_requests()
    }

    pub fn event_processing_overhead(&self) -> Duration {
        *self.event_processing_overhead.borrow()
    }

    pub fn wait_for_event(
        &self,
        timeout: Duration,
        mut handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), Error> {
        let mut fds = [libc::pollfd {
            fd: self.evtchn.as_raw_fd(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        }];

        let timeout = timeout
            .as_millis()
            .try_into()
            .map_err(|_| Error::InvalidTimeout)?;

        #[rustfmt::skip]
        let poll_result = unsafe {
            libc::poll(
                fds.as_mut_ptr() as _,
                fds.len() as _,
                timeout
            )
        };

        match poll_result {
            0 => return Err(Error::Timeout),
            -1 => return Err(Error::Io(std::io::Error::last_os_error())),
            _ => (),
        }

        struct OverheadGuard<'a, Arch>
        where
            Arch: Architecture + ArchAdapter,
        {
            driver: &'a XenDriver<Arch>,
            start: Instant,
        }

        impl<'a, Arch> OverheadGuard<'a, Arch>
        where
            Arch: Architecture + ArchAdapter,
        {
            fn new(driver: &'a XenDriver<Arch>) -> Self {
                Self {
                    driver,
                    start: Instant::now(),
                }
            }
        }

        impl<Arch> Drop for OverheadGuard<'_, Arch>
        where
            Arch: Architecture + ArchAdapter,
        {
            fn drop(&mut self) {
                let elapsed = Instant::now().duration_since(self.start);
                *self.driver.event_processing_overhead.borrow_mut() += elapsed;
            }
        }

        self.evtchn.wait()?;

        {
            let _overhead_guard = OverheadGuard::new(self);

            while self.ring.borrow().has_unconsumed_requests() {
                let mut event = self.ring.borrow_mut().get_request();
                Arch::process_event(self, &mut event, &mut handler)?;
                self.ring.borrow_mut().put_response(event);
            }
        }

        self.evtchn.notify()?;

        Ok(())
    }

    pub fn reset_state(&self) -> Result<(), Error> {
        Arch::reset_state(self)
    }
}
