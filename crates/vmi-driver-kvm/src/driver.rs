use std::{
    cell::RefCell,
    collections::HashMap,
    os::fd::RawFd,
    time::{Duration, Instant},
};

use kvm::{KvmMappedPage, KvmVmiMonitor, KvmVmiRing, KvmVmiSession, KvmVmiView};
use vmi_core::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiEvent,
    VmiEventResponse, VmiInfo, VmiMappedPage,
};

use crate::{ArchAdapter, Error};

/// Internal KVM VMI driver implementation.
pub struct KvmDriver<Arch: ArchAdapter> {
    pub(crate) session: KvmVmiSession,
    pub(crate) monitor: KvmVmiMonitor,
    pub(crate) rings: RefCell<Vec<KvmVmiRing>>,
    pub(crate) views: RefCell<HashMap<u16, KvmVmiView>>,
    pub(crate) event_processing_overhead: RefCell<Duration>,
    pub(crate) num_vcpus: u32,
    pub(crate) vcpu_fds: Vec<RawFd>,
    _arch: std::marker::PhantomData<Arch>,
}

impl<Arch: ArchAdapter> KvmDriver<Arch> {
    /// Create a new KVM VMI driver.
    ///
    /// `vm_fd`: raw fd of the KVM VM (from `/dev/kvm` -> `KVM_CREATE_VM`)
    /// `num_vcpus`: number of vCPUs in the VM
    /// `vcpu_fds`: raw fds for each vCPU (for KVM_GET_REGS etc.)
    pub fn new(
        vm_fd: RawFd,
        num_vcpus: u32,
        vcpu_fds: Vec<RawFd>,
    ) -> Result<Self, Error> {
        let session = KvmVmiSession::new(vm_fd)?;
        let monitor = KvmVmiMonitor::new(session.clone());

        // Set up per-vCPU rings.
        let mut rings = Vec::new();
        for vcpu_id in 0..num_vcpus {
            rings.push(KvmVmiRing::new(session.clone(), vcpu_id)?);
        }

        // Enable mem_access events so EPT violations on alternate views
        // are delivered to the agent instead of silently looping.
        let ctrl = kvm::sys::kvm_vmi_control_event {
            event: kvm::sys::KVM_VMI_EVENT_MEM_ACCESS,
            enable: 1,
            flags: 0,
            pad: 0,
            __bindgen_anon_1: kvm::sys::kvm_vmi_control_event__bindgen_ty_1::default(),
        };
        monitor.control_event(&ctrl)?;

        Ok(Self {
            session,
            monitor,
            rings: RefCell::new(rings),
            views: RefCell::new(HashMap::new()),
            event_processing_overhead: RefCell::new(Duration::ZERO),
            num_vcpus,
            vcpu_fds,
            _arch: std::marker::PhantomData,
        })
    }

    /// Returns information about the virtual machine.
    pub fn info(&self) -> Result<VmiInfo, Error> {
        Ok(VmiInfo {
            page_size: <Arch as Architecture>::PAGE_SIZE,
            page_shift: <Arch as Architecture>::PAGE_SHIFT,
            max_gfn: Gfn::new(0), // KVM doesn't expose max GFN directly
            vcpus: self.num_vcpus as u16,
        })
    }

    /// Pause all vCPUs.
    pub fn pause(&self) -> Result<(), Error> {
        Ok(self.session.pause_vm()?)
    }

    /// Resume all vCPUs.
    pub fn resume(&self) -> Result<(), Error> {
        Ok(self.session.unpause_vm()?)
    }

    /// Read a guest physical page.
    pub fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, Error> {
        let page = KvmMappedPage::new(self.session.fd(), gfn.into(), false)?;
        Ok(VmiMappedPage::new(page))
    }

    /// Write to a guest physical page.
    pub fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, Error> {
        let mut page = KvmMappedPage::new(self.session.fd(), gfn.into(), true)?;
        let offset = offset as usize;
        if offset + content.len() > <Arch as Architecture>::PAGE_SIZE as usize {
            return Err(Error::OutOfBounds);
        }
        page[offset..offset + content.len()].copy_from_slice(content);
        Ok(VmiMappedPage::new(page))
    }

    /// Query memory access permissions for a GFN in a view.
    pub fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, Error> {
        if view.0 == 0 {
            // View 0 is the default view. Return RWX for the default.
            return Ok(MemoryAccess::all());
        }
        match self.views.borrow().get(&view.0) {
            Some(v) => {
                let access = v.get_mem_access(gfn.into())?;
                Ok(MemoryAccess::from_bits_truncate(access))
            }
            None => Err(Error::ViewNotFound),
        }
    }

    /// Set memory access permissions for a GFN in a view.
    pub fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), Error> {
        if view.0 == 0 {
            return Err(Error::NotSupported);
        }
        match self.views.borrow().get(&view.0) {
            Some(v) => Ok(v.set_mem_access(gfn.into(), access.bits())?),
            None => Err(Error::ViewNotFound),
        }
    }

    /// Set memory access permissions with additional options.
    pub fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), Error> {
        if view.0 == 0 {
            return Err(Error::NotSupported);
        }

        let mut raw_access = access.bits();

        if options.contains(MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES) {
            // Map to KVM_VMI_ACCESS_PW which allows CPU paging writes
            // (A/D bit updates) without triggering EPT violations.
            raw_access |= kvm::sys::KVM_VMI_ACCESS_PW as u8;
        }

        match self.views.borrow().get(&view.0) {
            Some(v) => Ok(v.set_mem_access(gfn.into(), raw_access)?),
            None => Err(Error::ViewNotFound),
        }
    }

    /// Get vCPU registers via KVM_GET_REGS + KVM_GET_SREGS + KVM_GET_MSRS.
    ///
    /// Requires vCPU fds to have been provided at construction time.
    /// The vCPU must be paused (or blocked in KVM_RUN with mutex released)
    /// for this to succeed.
    pub fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, Error> {
        let idx = u16::from(vcpu) as usize;
        let vcpu_fd = *self.vcpu_fds.get(idx).ok_or(Error::NotSupported)?;
        Arch::registers_from_vcpu(vcpu_fd)
    }

    /// Set vCPU registers. Not yet implemented for direct vCPU fd access.
    pub fn set_registers(
        &self,
        _vcpu: VcpuId,
        _registers: Arch::Registers,
    ) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    /// Allocate a shadow GFN from the kernel's pool.
    pub fn allocate_gfn(&self) -> Result<Gfn, Error> {
        let gfn = self.session.alloc_gfn()?;
        Ok(Gfn::new(gfn))
    }

    /// Free a shadow GFN.
    pub fn free_gfn(&self, gfn: Gfn) -> Result<(), Error> {
        Ok(self.session.free_gfn(gfn.into())?)
    }

    /// Returns the default view (view 0).
    pub fn default_view(&self) -> View {
        View(0)
    }

    /// Create a new alternate memory view.
    pub fn create_view(&self, default_access: MemoryAccess) -> Result<View, Error> {
        let view = KvmVmiView::new(self.session.clone(), default_access.bits())?;
        let id = view.id() as u16;
        self.views.borrow_mut().insert(id, view);
        Ok(View(id))
    }

    /// Destroy an alternate memory view.
    pub fn destroy_view(&self, view: View) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }
        match self.views.borrow_mut().remove(&view.0) {
            Some(_view) => Ok(()), // Drop destroys the view
            None => Err(Error::ViewNotFound),
        }
    }

    /// Switch all vCPUs to a specific view.
    pub fn switch_to_view(&self, view: View) -> Result<(), Error> {
        let view_id = view.0 as u32;
        if view_id == 0 {
            self.session.switch_view(0)?;
            return Ok(());
        }
        match self.views.borrow().get(&view.0) {
            Some(v) => {
                v.switch()?;
                Ok(())
            }
            None => Err(Error::ViewNotFound),
        }
    }

    /// Remap a GFN in a view to point to a different backing page.
    pub fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }
        match self.views.borrow().get(&view.0) {
            Some(v) => Ok(v.change_gfn(old_gfn.into(), new_gfn.into())?),
            None => Err(Error::ViewNotFound),
        }
    }

    /// Reset a GFN in a view to its original mapping.
    pub fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), Error> {
        if view.0 == 0 {
            return Ok(());
        }
        match self.views.borrow().get(&view.0) {
            Some(v) => Ok(v.change_gfn(gfn.into(), kvm::consts::INVALID_GFN)?),
            None => Err(Error::ViewNotFound),
        }
    }

    /// Enable monitoring for a specific event type.
    pub fn monitor_enable(&self, option: Arch::EventMonitor) -> Result<(), Error> {
        Arch::monitor_enable(self, option)
    }

    /// Disable monitoring for a specific event type.
    pub fn monitor_disable(&self, option: Arch::EventMonitor) -> Result<(), Error> {
        Arch::monitor_disable(self, option)
    }

    /// Inject an interrupt into a vCPU.
    pub fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), Error> {
        Arch::inject_interrupt(self, vcpu, interrupt)
    }

    /// Returns the number of pending events across all rings.
    pub fn events_pending(&self) -> usize {
        self.rings
            .borrow()
            .iter()
            .map(|r| r.unconsumed_requests() as usize)
            .sum()
    }

    /// Returns the cumulative time spent processing events.
    pub fn event_processing_overhead(&self) -> Duration {
        *self.event_processing_overhead.borrow()
    }

    /// Wait for events, process them with the handler.
    pub fn wait_for_event(
        &self,
        timeout: Duration,
        mut handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), Error> {
        let rings = self.rings.borrow();
        let num_rings = rings.len();

        // Set up pollfds for all ring event fds.
        let mut fds: Vec<libc::pollfd> = rings
            .iter()
            .map(|r| libc::pollfd {
                fd: r.event_fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            })
            .collect();

        let timeout_ms: i32 = timeout
            .as_millis()
            .try_into()
            .map_err(|_| Error::InvalidTimeout)?;

        let poll_result =
            unsafe { libc::poll(fds.as_mut_ptr(), num_rings as libc::nfds_t, timeout_ms) };

        match poll_result {
            0 => return Err(Error::Timeout),
            -1 => return Err(Error::Io(std::io::Error::last_os_error())),
            _ => {}
        }

        drop(rings); // release borrow before processing

        let start = Instant::now();

        // Process events from all rings that have data.
        // Collect all events first, then ack them all at once.
        // This batches processing like Xen's shared ring design:
        // all vCPU events are processed before any vCPU is woken.
        let rings = self.rings.borrow();
        let mut ack_list: Vec<usize> = Vec::new();

        for (i, ring) in rings.iter().enumerate() {
            if fds[i].revents & libc::POLLIN != 0 {
                ring.drain_eventfd();

                while ring.has_unconsumed_requests() {
                    let event = unsafe { ring.current_event() };
                    Arch::process_event(self, event, &mut handler)?;
                    ring.advance_consumer();
                    ack_list.push(i);
                }
            }
        }

        // Signal all ack_fds at once to wake vCPUs simultaneously.
        for &i in &ack_list {
            rings[i].signal_ack();
        }

        *self.event_processing_overhead.borrow_mut() += start.elapsed();
        Ok(())
    }

    /// Reset all VMI state.
    pub fn reset_state(&self) -> Result<(), Error> {
        Arch::reset_state(self)
    }
}
