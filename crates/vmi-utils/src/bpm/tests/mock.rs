use std::cell::{Cell, RefCell};

use vmi_arch_amd64::{
    Amd64, Cr3, EventInterrupt, EventMemoryAccess, EventReason, EventSinglestep, Interrupt,
    MemoryAccessFlags, PageTableEntry, PageTableLevel, Registers,
};
use vmi_core::{
    AddressContext, Architecture, Gfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId, View,
    VmiCore, VmiDriver, VmiError, VmiEvent, VmiEventFlags, VmiInfo, VmiMappedPage, VmiRead,
    VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    arch::{EventInterrupt as _, EventReason as _},
};

use super::super::{Breakpoint, TapController};
use crate::test_support::{Amd64TestVm, DriverFault};

/// Controller operation recorded by the mock driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControllerCall {
    /// Installs a breakpoint at a physical address.
    Insert(Pa, View),

    /// Removes a breakpoint at a physical address.
    Remove(Pa, View),

    /// Starts monitoring a page.
    Monitor(Gfn, View),

    /// Stops monitoring a page.
    Unmonitor(Gfn, View),
}

/// Controller operation that should fail when next attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControllerFault {
    /// Fails breakpoint installation.
    Insert,

    /// Fails breakpoint removal.
    Remove,

    /// Fails page monitoring.
    Monitor,

    /// Fails page unmonitoring.
    Unmonitor,
}

/// Exposes the capabilities required by the BPM controllers and manager.
pub(super) struct MockBpmDriver {
    /// Shared guest state and low-level driver behavior.
    vm: Amd64TestVm,

    /// Calls made through the mock controller.
    controller_calls: RefCell<Vec<ControllerCall>>,

    /// Mock controller operation that should fail once.
    controller_fault: Cell<Option<ControllerFault>>,
}

impl MockBpmDriver {
    /// Creates an empty mock driver.
    fn new() -> Self {
        Self {
            vm: Amd64TestVm::without_call_recording(FIRST_SHADOW_GFN),
            controller_calls: RefCell::new(Vec::new()),
            controller_fault: Cell::new(None),
        }
    }

    /// Adds a zero-filled page.
    fn insert_page(&self, gfn: Gfn) {
        self.vm.insert_zeroed_page(gfn);
    }

    /// Writes a page-table entry at a physical address.
    fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        self.vm.write_pte(pa, pte);
    }

    /// Builds the paging hierarchy used by address-translation tests.
    fn build_hierarchy(&self, target_present: bool) {
        for gfn in [PML4_GFN, PDPT_GFN, PD_GFN, PT_GFN, DATA_GFN, OTHER_DATA_GFN] {
            self.insert_page(gfn);
        }

        self.write_pte(
            table_entry_pa(PML4_GFN, TEST_VA, PageTableLevel::Pml4),
            present_pte(PDPT_GFN),
        );
        self.write_pte(
            table_entry_pa(PDPT_GFN, TEST_VA, PageTableLevel::Pdpt),
            present_pte(PD_GFN),
        );
        self.write_pte(
            table_entry_pa(PD_GFN, TEST_VA, PageTableLevel::Pd),
            present_pte(PT_GFN),
        );
        self.write_pte(
            table_entry_pa(PT_GFN, TEST_VA, PageTableLevel::Pt),
            if target_present {
                present_pte(DATA_GFN)
            }
            else {
                PageTableEntry(0)
            },
        );
        self.write_pte(
            table_entry_pa(PT_GFN, OTHER_VA, PageTableLevel::Pt),
            present_pte(OTHER_DATA_GFN),
        );
    }

    /// Records a controller call and injects a configured failure.
    fn controller_call(&self, call: ControllerCall) -> Result<(), VmiError> {
        self.controller_calls.borrow_mut().push(call);
        let fault = match call {
            ControllerCall::Insert(..) => ControllerFault::Insert,
            ControllerCall::Remove(..) => ControllerFault::Remove,
            ControllerCall::Monitor(..) => ControllerFault::Monitor,
            ControllerCall::Unmonitor(..) => ControllerFault::Unmonitor,
        };

        if self.controller_fault.get() == Some(fault) {
            self.controller_fault.set(None);
            return Err(VmiError::Other("injected controller failure"));
        }

        Ok(())
    }

    /// Returns the chronological mock-controller call history.
    pub(super) fn controller_calls(&self) -> Vec<ControllerCall> {
        self.controller_calls.borrow().clone()
    }

    /// Clears the mock-controller call history.
    pub(super) fn clear_controller_calls(&self) {
        self.controller_calls.borrow_mut().clear();
    }

    /// Configures one matching mock-controller operation to fail.
    pub(super) fn fail_controller(&self, fault: ControllerFault) {
        assert!(self.controller_fault.replace(Some(fault)).is_none());
    }

    /// Configures one read from the given GFN to fail.
    pub(super) fn fail_read(&self, gfn: Gfn) {
        self.vm.fail_on(DriverFault::Read(gfn));
    }

    /// Returns the current permissions for a page.
    pub(super) fn access(&self, gfn: Gfn, view: View) -> MemoryAccess {
        self.vm
            .memory_access(gfn, view)
            .expect("test VM memory access should not fail")
    }

    /// Returns the explicit mapping for a page in a view.
    pub(super) fn mapping(&self, gfn: Gfn, view: View) -> Option<Gfn> {
        self.vm.mapping(view, gfn)
    }

    /// Returns a copy of a guest page.
    pub(super) fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.vm.page(gfn)
    }

    /// Replaces bytes in a guest page without recording a driver operation.
    pub(super) fn set_bytes(&self, gfn: Gfn, offset: u64, content: &[u8]) {
        self.vm.set_bytes(gfn, offset, content);
    }
}

impl VmiDriver for MockBpmDriver {
    type Architecture = Amd64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.vm.info())
    }
}

impl VmiRead for MockBpmDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.vm.read_page(gfn)
    }
}

impl VmiWrite for MockBpmDriver {
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        self.vm.write_page(gfn, offset, content)
    }
}

impl VmiSetProtection for MockBpmDriver {
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        self.vm.set_memory_access(gfn, view, access)
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        self.vm
            .set_memory_access_with_options(gfn, view, access, options)
    }
}

impl VmiViewControl for MockBpmDriver {
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        self.vm.change_view_gfn(view, old_gfn, new_gfn)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.vm.reset_view_gfn(view, gfn)
    }
}

impl VmiVmControl for MockBpmDriver {
    fn pause(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn resume(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        self.vm.allocate_gfn()
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.vm.free_gfn(gfn)
    }

    fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: Interrupt) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }
}

/// Controller that records operations in its associated driver.
pub(super) struct MockController;

impl TapController for MockController {
    type Driver = MockBpmDriver;

    fn new() -> Self {
        Self
    }

    fn check_event(&self, event: &VmiEvent<Amd64>) -> Option<(View, Gfn)> {
        let interrupt = event.reason().as_software_breakpoint()?;
        let view = event.view()?;
        Some((view, interrupt.gfn()))
    }

    fn insert_breakpoint(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        vmi.driver()
            .controller_call(ControllerCall::Insert(pa, view))
    }

    fn remove_breakpoint(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        vmi.driver()
            .controller_call(ControllerCall::Remove(pa, view))
    }

    fn monitor(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        vmi.driver()
            .controller_call(ControllerCall::Monitor(gfn, view))
    }

    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Self::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        vmi.driver()
            .controller_call(ControllerCall::Unmonitor(gfn, view))
    }
}

/// First page-table GFN.
pub(super) const PML4_GFN: Gfn = Gfn(1);

/// Second page-table GFN.
pub(super) const PDPT_GFN: Gfn = Gfn(2);

/// Third page-table GFN.
pub(super) const PD_GFN: Gfn = Gfn(3);

/// Final page-table GFN.
pub(super) const PT_GFN: Gfn = Gfn(4);

/// Primary mapped data GFN.
pub(super) const DATA_GFN: Gfn = Gfn(5);

/// Secondary mapped data GFN.
pub(super) const OTHER_DATA_GFN: Gfn = Gfn(6);

/// First allocated shadow GFN.
pub(super) const FIRST_SHADOW_GFN: Gfn = Gfn(0x1000);

/// Primary test view.
pub(super) const VIEW: View = View(7);

/// Secondary test view.
pub(super) const OTHER_VIEW: View = View(8);

/// Primary virtual address with a nonzero page offset.
pub(super) const TEST_VA: Va = Va(0x1123);

/// Secondary virtual address on another page.
pub(super) const OTHER_VA: Va = Va(0x2123);

/// Primary address-translation root.
pub(super) const ROOT: Pa = Pa(PML4_GFN.0 << 12);

/// Secondary root used by global-breakpoint tests.
pub(super) const OTHER_ROOT: Pa = Pa(0x9000);

/// Returns a present page-table entry for a GFN.
fn present_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | 1)
}

/// Returns the physical address of one page-table entry.
fn table_entry_pa(gfn: Gfn, va: Va, level: PageTableLevel) -> Pa {
    Amd64::pa_from_gfn(gfn) + Amd64::va_index_for(va, level) * 8
}

/// Creates a VMI core with the primary address mapped or unmapped.
pub(super) fn test_vmi(target_present: bool) -> Result<VmiCore<MockBpmDriver>, VmiError> {
    let driver = MockBpmDriver::new();
    driver.build_hierarchy(target_present);
    let mut vmi = VmiCore::new(driver)?;
    vmi.disable_gfn_cache();
    Ok(vmi)
}

/// Returns the primary virtual address context.
pub(super) fn test_context() -> AddressContext {
    AddressContext::new(TEST_VA, ROOT)
}

/// Returns the secondary virtual address context.
pub(super) fn other_context() -> AddressContext {
    AddressContext::new(OTHER_VA, ROOT)
}

/// Returns the primary translated physical address.
pub(super) fn test_pa() -> Pa {
    Amd64::pa_from_gfn(DATA_GFN) + Amd64::va_offset(TEST_VA)
}

/// Returns the secondary translated physical address.
pub(super) fn other_pa() -> Pa {
    Amd64::pa_from_gfn(OTHER_DATA_GFN) + Amd64::va_offset(OTHER_VA)
}

/// Creates a breakpoint with explicit key and tag metadata.
pub(super) fn breakpoint(
    ctx: AddressContext,
    view: View,
    key: u8,
    tag: &'static str,
) -> Breakpoint<u8, &'static str> {
    Breakpoint::new(ctx, view)
        .with_key(key)
        .with_tag(tag)
        .into()
}

/// Creates a global breakpoint with explicit key and tag metadata.
pub(super) fn global_breakpoint(
    ctx: AddressContext,
    view: View,
    key: u8,
    tag: &'static str,
) -> Breakpoint<u8, &'static str> {
    Breakpoint::new(ctx, view)
        .global()
        .with_key(key)
        .with_tag(tag)
        .into()
}

/// Creates a software-breakpoint event.
pub(super) fn software_event(gfn: Gfn, view: Option<View>, va: Va, root: Pa) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: va.0,
        cr3: Cr3(root.0),
        ..Default::default()
    };

    VmiEvent::new(
        VcpuId(0),
        VmiEventFlags::default(),
        view,
        registers,
        EventReason::Interrupt(EventInterrupt {
            gfn,
            interrupt: Interrupt::breakpoint(1),
        }),
    )
}

/// Creates a memory-access event.
pub(super) fn memory_event(pa: Pa, view: Option<View>, access: MemoryAccess) -> VmiEvent<Amd64> {
    VmiEvent::new(
        VcpuId(0),
        VmiEventFlags::default(),
        view,
        Registers::default(),
        EventReason::MemoryAccess(EventMemoryAccess {
            pa,
            va: TEST_VA,
            access,
            flags: MemoryAccessFlags::default(),
        }),
    )
}

/// Creates an event that is not a breakpoint or memory access.
pub(super) fn unrelated_event(view: Option<View>) -> VmiEvent<Amd64> {
    VmiEvent::new(
        VcpuId(0),
        VmiEventFlags::default(),
        view,
        Registers::default(),
        EventReason::Singlestep(EventSinglestep { gfn: DATA_GFN }),
    )
}
