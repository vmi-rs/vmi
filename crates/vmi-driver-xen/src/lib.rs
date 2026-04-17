//! VMI driver for Xen hypervisor.

mod arch;
mod convert;
mod core;

use std::{
    cell::RefCell,
    collections::HashMap,
    os::fd::AsRawFd as _,
    time::{Duration, Instant},
};

use vmi_core::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiDriver, VmiError,
    VmiEvent, VmiEventResponse, VmiInfo, VmiMappedPage,
    driver::{
        VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead, VmiSetProtection,
        VmiSetRegisters, VmiViewControl, VmiVmControl, VmiWrite,
    },
};
use xen::{
    XenAltP2M, XenAltP2MView, XenControl, XenDeviceModel, XenDomain, XenDomainId, XenDomainInfo,
    XenEventChannelPort, XenForeignMemory, XenForeignMemoryProtection, XenMonitor,
    ctrl::VmEventRing,
};

pub use self::arch::ArchAdapter;
use self::convert::{FromExt, IntoExt, TryFromExt};

/// VMI driver for Xen hypervisor.
pub struct VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
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

impl<Arch> Drop for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn drop(&mut self) {
        let max_memkb = self.info.max_pages * Arch::PAGE_SIZE / 1024;

        let _ = self.domain.set_max_mem(max_memkb);
        let _ = self.monitor.emul_unimplemented(false);
        let _ = self.monitor.inguest_pagefault(false);
    }
}

impl<Arch> VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a new VMI driver for Xen hypervisor.
    pub fn new(domain_id: XenDomainId) -> Result<Self, VmiError> {
        let xc = XenControl::new().map_err(VmiError::driver)?;
        let domain = xc.domain(domain_id).map_err(VmiError::driver)?;
        domain.set_max_mem(u64::MAX).map_err(VmiError::driver)?;

        let devicemodel = domain.device_model().map_err(VmiError::driver)?;
        let (monitor, ring) = domain.monitor().map_err(VmiError::driver)?;
        let altp2m = domain.altp2m().map_err(VmiError::driver)?;
        let evtchn = monitor.channel().map_err(VmiError::driver)?;
        let foreign_memory = XenForeignMemory::new().map_err(VmiError::driver)?;
        let info = domain.info().map_err(VmiError::driver)?;

        monitor.inguest_pagefault(true).map_err(VmiError::driver)?;
        monitor.emul_unimplemented(true).map_err(VmiError::driver)?;

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
}

impl<Arch> VmiDriver for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: Arch::PAGE_SIZE,
            page_shift: Arch::PAGE_SHIFT,
            max_gfn: Gfn::new(self.domain.maximum_gpfn().map_err(VmiError::driver)?),
            vcpus: self.info.max_vcpu_id + 1,
        })
    }
}

impl<Arch> VmiRead for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let page = self
            .foreign_memory
            .map(
                self.domain.id(),
                XenForeignMemoryProtection::READ,
                &[u64::from(gfn)],
                None,
            )
            .map_err(VmiError::driver)?;

        Ok(VmiMappedPage::new(page))
    }
}

impl<Arch> VmiWrite for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        let mut page = self
            .foreign_memory
            .map(
                self.domain.id(),
                XenForeignMemoryProtection::WRITE,
                &[u64::from(gfn)],
                None,
            )
            .map_err(VmiError::driver)?;

        let offset = offset as usize;
        if offset + content.len() > Arch::PAGE_SIZE as usize {
            return Err(VmiError::OutOfBounds);
        }

        page[offset..offset + content.len()].copy_from_slice(content);

        Ok(VmiMappedPage::new(page))
    }
}

impl<Arch> VmiQueryProtection for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        if view.0 == 0 {
            return Ok(self
                .domain
                .get_mem_access(gfn.0)
                .map_err(VmiError::driver)?
                .into_ext());
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => Ok(view
                .get_mem_access(gfn.0)
                .map_err(VmiError::driver)?
                .into_ext()),
            None => Err(VmiError::ViewNotFound),
        }
    }
}

impl<Arch> VmiSetProtection for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        tracing::trace!(%gfn, %view, %access, "set memory access");

        if view.0 == 0 {
            return self
                .domain
                .set_mem_access(gfn.into(), access.into_ext())
                .map_err(VmiError::driver);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => view
                .set_mem_access(gfn.into(), access.into_ext())
                .map_err(VmiError::driver),
            None => Err(VmiError::ViewNotFound),
        }
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        tracing::trace!(%gfn, %view, %access, "set memory access");

        let mut xen_access = access.into_ext();

        if options.contains(MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES) {
            if access != MemoryAccess::R {
                return Err(VmiError::NotSupported);
            }

            xen_access = xen::MemoryAccess::R_PW;
        }

        if view.0 == 0 {
            return self
                .domain
                .set_mem_access(gfn.into(), xen_access)
                .map_err(VmiError::driver);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => view
                .set_mem_access(gfn.into(), xen_access)
                .map_err(VmiError::driver),
            None => Err(VmiError::ViewNotFound),
        }
    }
}

impl<Arch> VmiQueryRegisters for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Arch::registers(self, vcpu)
    }
}

impl<Arch> VmiSetRegisters for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn set_registers(&self, vcpu: VcpuId, registers: Arch::Registers) -> Result<(), VmiError> {
        Arch::set_registers(self, vcpu, registers)
    }
}

impl<Arch> VmiViewControl for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, default_access: MemoryAccess) -> Result<View, VmiError> {
        let view = self
            .altp2m
            .create_view(default_access.into_ext())
            .map_err(VmiError::driver)?;

        let id = view.id();
        self.views.borrow_mut().insert(id, view);

        Ok(View(id))
    }

    fn destroy_view(&self, view: View) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow_mut().remove(&view.0) {
            // View is destroyed automatically when it goes out of scope
            Some(_view) => Ok(()),
            None => Err(VmiError::ViewNotFound),
        }
    }

    fn switch_to_view(&self, view: View) -> Result<(), VmiError> {
        if view.0 == 0 {
            return self.altp2m.reset_view().map_err(VmiError::driver);
        }

        match self.views.borrow().get(&view.0) {
            Some(view) => view.switch().map_err(VmiError::driver),
            None => Err(VmiError::ViewNotFound),
        }
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow().get(&view.0) {
            // WARNING: This will change access permissions of the GFN!
            Some(view) => view
                .change_gfn(old_gfn.into(), new_gfn.into())
                .map_err(VmiError::driver),
            None => Err(VmiError::ViewNotFound),
        }
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        match self.views.borrow().get(&view.0) {
            // WARNING: This will change access permissions of the GFN!
            Some(view) => view
                .change_gfn(gfn.into(), u64::MAX)
                .map_err(VmiError::driver),
            None => Err(VmiError::ViewNotFound),
        }
    }
}

impl<Arch> VmiEventControl for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn monitor_enable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Arch::monitor_enable(self, option)
    }

    fn monitor_disable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Arch::monitor_disable(self, option)
    }

    fn events_pending(&self) -> usize {
        self.ring.borrow().unconsumed_requests()
    }

    fn event_processing_overhead(&self) -> Duration {
        *self.event_processing_overhead.borrow()
    }

    fn wait_for_event(
        &self,
        timeout: Duration,
        mut handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), VmiError> {
        let mut fds = [libc::pollfd {
            fd: self.evtchn.as_raw_fd(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        }];

        let timeout = timeout
            .as_millis()
            .try_into()
            .map_err(|_| VmiError::InvalidTimeout)?;

        #[rustfmt::skip]
        let poll_result = unsafe {
            libc::poll(
                fds.as_mut_ptr() as _,
                fds.len() as _,
                timeout
            )
        };

        match poll_result {
            0 => return Err(VmiError::Timeout),
            -1 => return Err(VmiError::Io(std::io::Error::last_os_error())),
            _ => (),
        }

        struct OverheadGuard<'a, Arch>
        where
            Arch: ArchAdapter,
        {
            driver: &'a VmiXenDriver<Arch>,
            start: Instant,
        }

        impl<'a, Arch> OverheadGuard<'a, Arch>
        where
            Arch: ArchAdapter,
        {
            fn new(driver: &'a VmiXenDriver<Arch>) -> Self {
                Self {
                    driver,
                    start: Instant::now(),
                }
            }
        }

        impl<Arch> Drop for OverheadGuard<'_, Arch>
        where
            Arch: ArchAdapter,
        {
            fn drop(&mut self) {
                let elapsed = Instant::now().duration_since(self.start);
                *self.driver.event_processing_overhead.borrow_mut() += elapsed;
            }
        }

        self.evtchn.wait().map_err(VmiError::driver)?;

        {
            let _overhead_guard = OverheadGuard::new(self);

            while self.ring.borrow().has_unconsumed_requests() {
                let mut event = self.ring.borrow_mut().get_request();
                Arch::process_event(self, &mut event, &mut handler)?;
                self.ring.borrow_mut().put_response(event);
            }
        }

        self.evtchn.notify().map_err(VmiError::driver)?;

        Ok(())
    }
}

impl<Arch> VmiVmControl for VmiXenDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn pause(&self) -> Result<(), VmiError> {
        self.domain.pause().map_err(VmiError::driver)
    }

    fn resume(&self) -> Result<(), VmiError> {
        self.domain.unpause().map_err(VmiError::driver)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        let gfn = Gfn::new(self.domain.maximum_gpfn().map_err(VmiError::driver)?) + 1;
        self.allocate_gfn_at(gfn)?;
        Ok(gfn)
    }

    fn allocate_gfn_at(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.domain
            .populate_physmap_exact(0, 0, &[gfn.into()])
            .map_err(VmiError::driver)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.domain
            .decrease_reservation_exact(0, &[gfn.into()])
            .map_err(VmiError::driver)
    }

    fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), VmiError> {
        Arch::inject_interrupt(self, vcpu, interrupt)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Arch::reset_state(self)
    }
}
