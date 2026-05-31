//! VMI driver for KVM.

mod arch;
mod convert;
mod core;

use std::{
    cell::RefCell,
    collections::HashSet,
    marker::PhantomData,
    ops::Deref,
    os::fd::{BorrowedFd, OwnedFd},
    time::Duration,
};

use kvm::{KvmGuestMemory, KvmMappedPage, KvmVcpu, KvmVmi, KvmVmiRing, ViewId};
use vmi_core::{
    Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiDriver, VmiError, VmiEvent,
    VmiEventResponse, VmiInfo, VmiMappedPage,
    driver::{
        VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead, VmiSetProtection,
        VmiSetRegisters, VmiViewControl, VmiVmControl, VmiWrite,
    },
};

pub use self::arch::ArchAdapter;
pub(crate) use self::convert::FromExt;

/// Wraps a mapped guest page so it can back a [`VmiMappedPage`].
struct KvmPageBacking(KvmMappedPage);

impl Deref for KvmPageBacking {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// VMI driver for KVM.
pub struct VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// The VMI session owning the `vmi_fd`.
    pub(crate) session: KvmVmi,

    /// Duplicated vCPU fds indexed by vCPU id.
    pub(crate) vcpus: Vec<KvmVcpu>,

    /// Per-vCPU event rings, set up lazily on first monitor enable.
    pub(crate) rings: RefCell<Vec<Option<KvmVmiRing>>>,

    /// Tracked alternate view ids (view 0 is implicit and not tracked).
    pub(crate) views: RefCell<HashSet<u32>>,

    /// Cumulative time spent processing events.
    pub(crate) event_processing_overhead: RefCell<Duration>,

    /// Marker for the architecture type parameter.
    pub(crate) _arch: PhantomData<Arch>,
}

impl<Arch> VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a driver from an already-opened VM fd and per-vCPU fds.
    /// `vcpu_fds` is indexed by vCPU id.
    pub fn new(vm_fd: BorrowedFd, vcpu_fds: Vec<OwnedFd>) -> Result<Self, VmiError> {
        let session = KvmVmi::create(vm_fd).map_err(VmiError::driver)?;
        let vcpus = vcpu_fds.into_iter().map(KvmVcpu::new).collect::<Vec<_>>();
        let n = vcpus.len();
        Ok(Self {
            session,
            vcpus,
            rings: RefCell::new((0..n).map(|_| None).collect()),
            views: RefCell::new(HashSet::new()),
            event_processing_overhead: RefCell::new(Duration::from_millis(0)),
            _arch: PhantomData,
        })
    }
}

impl<Arch> Drop for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn drop(&mut self) {
        let _ = Arch::reset_state(self);
    }
}

impl<Arch> VmiDriver for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: Arch::PAGE_SIZE,
            page_shift: Arch::PAGE_SHIFT,
            max_gfn: Gfn::new(0),
            vcpus: self.vcpus.len() as u16,
        })
    }
}

impl<Arch> VmiRead for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let page =
            KvmGuestMemory::map_page(self.session.fd(), gfn.into(), Arch::PAGE_SHIFT as u8, false)
                .map_err(VmiError::driver)?;

        Ok(VmiMappedPage::new(KvmPageBacking(page)))
    }
}

impl<Arch> VmiWrite for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        let offset = offset as usize;
        if offset + content.len() > Arch::PAGE_SIZE as usize {
            return Err(VmiError::OutOfBounds);
        }

        let mut page =
            KvmGuestMemory::map_page(self.session.fd(), gfn.into(), Arch::PAGE_SHIFT as u8, true)
                .map_err(VmiError::driver)?;

        page.as_mut_slice()[offset..offset + content.len()].copy_from_slice(content);

        Ok(VmiMappedPage::new(KvmPageBacking(page)))
    }
}

impl<Arch> VmiQueryProtection for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        let bits = self
            .session
            .get_mem_access(ViewId(u32::from(view.0)), gfn.into())
            .map_err(VmiError::driver)?;

        Ok(MemoryAccess::from_ext(bits))
    }
}

impl<Arch> VmiSetProtection for VmiKvmDriver<Arch>
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

        self.session
            .set_mem_access(ViewId(u32::from(view.0)), gfn.into(), u8::from_ext(access))
            .map_err(VmiError::driver)
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        tracing::trace!(%gfn, %view, %access, "set memory access");

        let mut bits = u8::from_ext(access);

        if options.contains(MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES) {
            if access != MemoryAccess::R {
                return Err(VmiError::NotSupported);
            }

            bits = kvm::sys::KVM_VMI_ACCESS_PW as u8;
        }

        self.session
            .set_mem_access(ViewId(u32::from(view.0)), gfn.into(), bits)
            .map_err(VmiError::driver)
    }
}

impl<Arch> VmiQueryRegisters for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Arch::registers(self, vcpu)
    }
}

impl<Arch> VmiSetRegisters for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn set_registers(&self, vcpu: VcpuId, registers: Arch::Registers) -> Result<(), VmiError> {
        Arch::set_registers(self, vcpu, registers)
    }
}

impl<Arch> VmiViewControl for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, default_access: MemoryAccess) -> Result<View, VmiError> {
        let id = self
            .session
            .create_view(u8::from_ext(default_access))
            .map_err(VmiError::driver)?;

        self.views.borrow_mut().insert(id.0);

        Ok(View(id.0 as u16))
    }

    fn destroy_view(&self, view: View) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        self.session
            .destroy_view(ViewId(u32::from(view.0)))
            .map_err(VmiError::driver)?;
        self.views.borrow_mut().remove(&u32::from(view.0));

        Ok(())
    }

    fn switch_to_view(&self, view: View) -> Result<(), VmiError> {
        self.session
            .switch_view(ViewId(u32::from(view.0)))
            .map_err(VmiError::driver)
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        self.session
            .change_gfn(ViewId(u32::from(view.0)), old_gfn.into(), new_gfn.into())
            .map_err(VmiError::driver)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        // KVM_VMI_INVALID_GFN (`~(__u64)0`) reverts the GFN to its host mapping.
        // kvm-sys exposes it as a signed `-1` const, recovered here with `as u64`.
        let invalid_gfn = kvm::sys::KVM_VMI_INVALID_GFN as u64;
        self.session
            .change_gfn(ViewId(u32::from(view.0)), gfn.into(), invalid_gfn)
            .map_err(VmiError::driver)
    }
}

impl<Arch> VmiVmControl for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn pause(&self) -> Result<(), VmiError> {
        self.session.pause_vm().map_err(VmiError::driver)
    }

    fn resume(&self) -> Result<(), VmiError> {
        self.session.unpause_vm().map_err(VmiError::driver)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        let gfn = self.session.alloc_gfn().map_err(VmiError::driver)?;
        Ok(Gfn::new(gfn))
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.session.free_gfn(gfn.into()).map_err(VmiError::driver)
    }

    fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), VmiError> {
        Arch::inject_interrupt(self, vcpu, interrupt)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Arch::reset_state(self)
    }
}

impl<Arch> VmiEventControl for VmiKvmDriver<Arch>
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
        self.rings
            .borrow()
            .iter()
            .filter(|ring| ring.as_ref().is_some_and(KvmVmiRing::has_pending))
            .count()
    }

    fn event_processing_overhead(&self) -> Duration {
        *self.event_processing_overhead.borrow()
    }

    fn wait_for_event(
        &self,
        timeout: Duration,
        handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), VmiError> {
        Arch::process_event(self, timeout, handler)
    }
}
