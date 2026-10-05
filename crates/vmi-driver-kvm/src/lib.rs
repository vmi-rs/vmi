//! VMI driver for KVM.
//!
//! The driver introspects a running VM through the KVM VMI interface of the
//! host kernel. It takes the VM fd and the vCPU fds of the VM, which
//! `kvm::attach::from_pid` duplicates from a running VMM process.
//!
//! Guest memory is mapped through the `vmi_fd` in host pages, and KVM keys
//! memory access permissions and view remaps by host page as well. A guest
//! page smaller than a host page is served as a window into the host page that
//! holds it. Protection and view changes then apply to the whole host page.

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

/// Guest page mapped through the `vmi_fd`.
///
/// The mapping covers the whole host page that holds the guest page, and the
/// window selects the guest page inside it.
struct KvmPageBacking {
    /// Mapping of the host page.
    page: KvmMappedPage,

    /// Byte offset of the guest page inside the host page.
    offset: usize,

    /// Size of the guest page in bytes.
    len: usize,
}

impl KvmPageBacking {
    /// Returns the guest page for writing.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.page.as_mut_slice()[self.offset..self.offset + self.len]
    }
}

impl Deref for KvmPageBacking {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.page.as_slice()[self.offset..self.offset + self.len]
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

    /// Number of bits between a guest frame number and the number of the host
    /// frame that holds it.
    ///
    /// The value is zero when the guest page size equals the host page size.
    frame_shift: u32,

    /// Exclusive upper bound of guest RAM in host frames, cached from
    /// `KVM_VMI_GET_MEM_INFO` at construction.
    ///
    /// The VMM backs no frame at or above this bound with RAM, and mapping
    /// such a frame through the `vmi_fd` raises `SIGBUS` on first access, so
    /// reads of it are rejected up front.
    max_host_frame: u64,
}

impl<Arch> VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a driver from an already-opened VM fd and per-vCPU fds.
    ///
    /// `vcpu_fds` is indexed by vCPU id. The guest page size of `Arch` must
    /// not exceed the host page size.
    pub fn new(vm_fd: BorrowedFd, vcpu_fds: Vec<OwnedFd>) -> Result<Self, VmiError> {
        let host_shift = kvm::host_page_size().trailing_zeros();
        let guest_shift = Arch::PAGE_SHIFT as u32;
        let frame_shift = match host_shift.checked_sub(guest_shift) {
            Some(frame_shift) => frame_shift,
            None => {
                return Err(VmiError::Other(
                    "guest page size exceeds the host page size",
                ));
            }
        };

        let session = KvmVmi::create(vm_fd).map_err(VmiError::driver)?;
        let vcpus = vcpu_fds.into_iter().map(KvmVcpu::new).collect::<Vec<_>>();
        let vcpu_count = vcpus.len();

        // The guest RAM layout is fixed once the VMM has set up its memslots.
        let max_host_frame = session.mem_info().map_err(VmiError::driver)?;

        Ok(Self {
            session,
            vcpus,
            rings: RefCell::new((0..vcpu_count).map(|_| None).collect()),
            views: RefCell::new(HashSet::new()),
            event_processing_overhead: RefCell::new(Duration::ZERO),
            _arch: PhantomData,
            frame_shift,
            max_host_frame,
        })
    }

    /// Returns the host frame (KVM gfn) that holds a guest frame.
    ///
    /// A frame allocated by [`VmiVmControl::allocate_gfn`] maps back to the
    /// kernel's shadow frame.
    fn host_frame(&self, gfn: Gfn) -> u64 {
        gfn.0 >> self.frame_shift
    }

    /// Returns the first guest frame held by a host frame.
    fn guest_frame(&self, host_frame: u64) -> Gfn {
        Gfn(host_frame << self.frame_shift)
    }

    /// Maps the guest page `gfn` through the `vmi_fd`.
    fn map_gfn(&self, gfn: Gfn, write: bool) -> Result<KvmPageBacking, VmiError> {
        // Shadow frames are backed by the kernel and sit above guest RAM.
        let host_frame = self.host_frame(gfn);
        if host_frame < kvm::sys::KVM_VMI_SHADOW_GFN_BASE && host_frame >= self.max_host_frame {
            return Err(VmiError::OutOfBounds);
        }

        let page = KvmGuestMemory::map_page(self.session.fd(), host_frame, write)
            .map_err(VmiError::driver)?;

        let index = gfn.0 & ((1 << self.frame_shift) - 1);
        Ok(KvmPageBacking {
            page,
            offset: (index << Arch::PAGE_SHIFT) as usize,
            len: Arch::PAGE_SIZE as usize,
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
        let max_gfn = match self.max_host_frame {
            0 => Gfn(0),
            max_host_frame => Gfn(self.guest_frame(max_host_frame).0 - 1),
        };

        Ok(VmiInfo {
            page_size: Arch::PAGE_SIZE,
            page_shift: Arch::PAGE_SHIFT,
            max_gfn,
            vcpus: self.vcpus.len() as u16,
        })
    }
}

impl<Arch> VmiRead for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(VmiMappedPage::new(self.map_gfn(gfn, false)?))
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

        let mut page = self.map_gfn(gfn, true)?;
        page.as_mut_slice()[offset..offset + content.len()].copy_from_slice(content);

        Ok(VmiMappedPage::new(page))
    }
}

impl<Arch> VmiQueryProtection for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        let (access, _options) = self.memory_access_with_options(gfn, view)?;
        Ok(access)
    }

    fn memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
    ) -> Result<(MemoryAccess, MemoryAccessOptions), VmiError> {
        let access = self
            .session
            .get_mem_access(ViewId(u32::from(view.0)), self.host_frame(gfn))
            .map_err(VmiError::driver)?;

        let options = if access.contains(MemAccess::PW) {
            MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES
        }
        else {
            MemoryAccessOptions::empty()
        };

        Ok((MemoryAccess::from_ext(access), options))
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
                self.host_frame(gfn),
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
            .set_mem_access(ViewId(u32::from(view.0)), self.host_frame(gfn), bits)
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
                self.host_frame(old_gfn),
                self.host_frame(new_gfn),
            )
            .map_err(VmiError::driver)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        if view.0 == 0 {
            return Ok(());
        }

        // kvm::INVALID_GFN (`~(__u64)0`) reverts the host frame to its host
        // mapping.
        self.session
            .change_gfn(
                ViewId(u32::from(view.0)),
                self.host_frame(gfn),
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

    /// Allocates a shadow page and returns the first guest frame it holds.
    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        let host_frame = self.session.alloc_gfn().map_err(VmiError::driver)?;
        Ok(self.guest_frame(host_frame))
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.session
            .free_gfn(self.host_frame(gfn))
            .map_err(VmiError::driver)
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
