//! VMI driver for KVM.

mod arch;
mod convert;

use std::{
    cell::RefCell,
    collections::HashSet,
    marker::PhantomData,
    ops::Deref,
    os::fd::{BorrowedFd, OwnedFd},
    time::Duration,
};

use kvm::{KvmGuestMemory, KvmMappedPage, KvmVcpu, KvmVmi, KvmVmiRing, MemAccess, ViewId};
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

impl<Arch> VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Converts a gfn expressed in the generic (guest-page) units the upper
    /// layers use into the host-page KVM gfn the kernel VMI ABI works in.
    ///
    /// The kernel keys views, memory-access permissions, and gfn remaps by
    /// host-page frame. On a host whose page size exceeds the guest granule
    /// (a 16K arm64 host introspecting a 4K guest) a guest-page gfn must be
    /// shifted down by `host_shift - guest_shift` to name its enclosing host
    /// frame. A shadow gfn is already a host-page kernel allocation, so it
    /// passes through unchanged. On a host whose page size equals the guest
    /// granule the shift delta is zero and this is the identity.
    fn to_host_gfn(gfn: u64) -> u64 {
        if gfn >= kvm::sys::KVM_VMI_SHADOW_GFN_BASE {
            gfn
        }
        else {
            let host_shift = kvm::host_page_size().trailing_zeros();
            let guest_shift = Arch::PAGE_SHIFT as u32;
            gfn >> (host_shift - guest_shift)
        }
    }

    /// Computes the in-kernel auto-step mask for the host page enclosing `gfn`:
    /// a bit set for every 4K sub-page fused into that host page except the one
    /// holding `gfn` itself.
    ///
    /// On a host whose page size matches the guest granule there is no fusion,
    /// so the result is 0 and the kernel sees a plain access. A shadow gfn is
    /// already a whole host-page allocation, so it has no neighbors and also
    /// yields 0.
    fn neighbor_autostep_mask(gfn: u64) -> u16 {
        if gfn >= kvm::sys::KVM_VMI_SHADOW_GFN_BASE {
            return 0;
        }
        let host_shift = kvm::host_page_size().trailing_zeros();
        let guest_shift = Arch::PAGE_SHIFT as u32;
        let nsub = 1u32 << (host_shift - guest_shift);
        let index = (gfn as u32) & (nsub - 1);
        let full = (1u32 << nsub) - 1;
        (full & !(1u32 << index)) as u16
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

    fn view_page_shift(&self) -> u32 {
        // The kernel keys views and shadow pages by host frame, so on a 16K
        // arm64 host over a 4K guest a view page is the 16K host page.
        kvm::host_page_size().trailing_zeros()
    }
}

impl<Arch> VmiWrite for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        let offset = offset as usize;

        // A shadow gfn maps a full host page, so a shadow write may span the
        // whole host frame (a 16K shadow on a 16K host). An ordinary guest gfn
        // stays bounded by the guest page. On a host whose page size equals the
        // guest granule both limits coincide.
        let page_limit = if u64::from(gfn) >= kvm::sys::KVM_VMI_SHADOW_GFN_BASE {
            kvm::host_page_size()
        }
        else {
            Arch::PAGE_SIZE as usize
        };
        if offset + content.len() > page_limit {
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
        Ok(MemoryAccess::from_ext(
            self.session
                .get_mem_access(ViewId(u32::from(view.0)), Self::to_host_gfn(gfn.into()))
                .map_err(VmiError::driver)?,
        ))
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
            .set_mem_access(
                ViewId(u32::from(view.0)),
                Self::to_host_gfn(gfn.into()),
                MemAccess::from_ext(access),
            )
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

        if options.contains(MemoryAccessOptions::AUTO_STEP_NEIGHBORS) {
            return self
                .session
                .set_mem_access_autostep(
                    ViewId(u32::from(view.0)),
                    Self::to_host_gfn(gfn.into()),
                    MemAccess::from_ext(access),
                    Self::neighbor_autostep_mask(gfn.into()),
                )
                .map_err(VmiError::driver);
        }

        let bits = if options.contains(MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES) {
            if access != MemoryAccess::R {
                return Err(VmiError::NotSupported);
            }

            // Keep R set alongside PW. The page must stay readable so the EPT
            // entry is present: with PW alone the entry has no R/W/X bits, which
            // the CPU treats as not-present, so every access faults before the
            // kernel can classify it as a write violation, looping forever
            // instead of delivering a mem_access event. R|PW matches the KVM
            // selftest and the Xen driver's R_PW.
            MemAccess::R | MemAccess::PW
        }
        else {
            MemAccess::from_ext(access)
        };

        self.session
            .set_mem_access(
                ViewId(u32::from(view.0)),
                Self::to_host_gfn(gfn.into()),
                bits,
            )
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
            .create_view(MemAccess::from_ext(default_access))
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
            .change_gfn(
                ViewId(u32::from(view.0)),
                Self::to_host_gfn(old_gfn.into()),
                Self::to_host_gfn(new_gfn.into()),
            )
            .map_err(VmiError::driver)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        // kvm::INVALID_GFN (`~(__u64)0`) reverts the GFN to its host mapping.
        self.session
            .change_gfn(
                ViewId(u32::from(view.0)),
                Self::to_host_gfn(gfn.into()),
                kvm::INVALID_GFN,
            )
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
