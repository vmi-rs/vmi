use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    marker::PhantomData,
};

use vmi_arch_amd64::{
    Amd64, Cr3, EventInterrupt, EventMemoryAccess, EventReason, EventSinglestep, Interrupt,
    MemoryAccessFlags, PageTableEntry, PageTableLevel, Registers,
};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId,
    View, VmiCore, VmiDriver, VmiError, VmiEvent, VmiEventFlags, VmiInfo, VmiMappedPage,
    VmiQueryProtection, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    arch::{EventInterrupt as _, EventReason as _},
};

use super::{Breakpoint, BreakpointController, BreakpointManager, MemoryController, TapController};
use crate::ptm::{PageEntryUpdate, PageTableMonitorEvent};

///////////////////////////////////////////////////////////////////////////////
// Mock Driver
///////////////////////////////////////////////////////////////////////////////

/// A single driver operation recorded by the mock, used to assert the exact
/// sequence of hypervisor interactions a controller performs.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    /// `read_page(gfn)`.
    ReadPage(Gfn),

    /// `write_page(gfn, offset, content)`, recording only the length.
    WritePage { gfn: Gfn, offset: u64, len: usize },

    /// `allocate_gfn()` returning the given frame.
    AllocateGfn(Gfn),

    /// `change_view_gfn(view, old, new)`.
    ChangeViewGfn { view: View, old: Gfn, new: Gfn },

    /// `reset_view_gfn(view, gfn)`.
    ResetViewGfn { view: View, gfn: Gfn },

    /// `set_memory_access(gfn, view, access)`.
    SetMemoryAccess {
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    },
}

/// A driver operation that can be armed to fail on a chosen invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// `read_page`.
    ReadPage,

    /// `write_page`.
    WritePage,

    /// `allocate_gfn`.
    AllocateGfn,

    /// `change_view_gfn`.
    ChangeView,

    /// `reset_view_gfn`.
    ResetView,

    /// `set_memory_access`.
    SetMemoryAccess,
}

/// In-memory stand-in for a VMI driver.
///
/// Combines the memory/view/allocation model the interceptor needs with the
/// memory-access protection model the controllers use, records every operation
/// for assertions, and can inject faults into any single driver call.
struct MockDriver {
    /// Guest physical pages, each 4 KiB, indexed by frame number.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,

    /// Active per-view remappings, mapping `(view, original)` to its shadow.
    views: RefCell<HashMap<(View, Gfn), Gfn>>,

    /// Per-`(view, gfn)` memory-access protection.
    access: RefCell<HashMap<(View, Gfn), MemoryAccess>>,

    /// Ordered log of every recorded operation.
    log: RefCell<Vec<Call>>,

    /// Next frame number handed out by `allocate_gfn`.
    next_gfn: Cell<u64>,

    /// Per-operation invocation counters.
    counters: RefCell<HashMap<Op, usize>>,

    /// Armed faults, mapping an operation to the 1-based invocation to fail.
    faults: RefCell<HashMap<Op, usize>>,
}

/// Base frame number for shadow pages allocated by the mock. Chosen well above
/// the low frames the tests use for guest and page-table pages.
const SHADOW_BASE: u64 = 0x1000;

impl MockDriver {
    /// Creates an empty driver with no pages and no armed faults.
    fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            views: RefCell::new(HashMap::new()),
            access: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            next_gfn: Cell::new(SHADOW_BASE),
            counters: RefCell::new(HashMap::new()),
            faults: RefCell::new(HashMap::new()),
        }
    }

    /// Inserts a 4 KiB page at `gfn` filled with `byte`.
    fn fill_page(&self, gfn: Gfn, byte: u8) {
        self.pages.borrow_mut().insert(gfn, vec![byte; 4096]);
    }

    /// Inserts a blank 4 KiB page at `gfn`.
    fn insert_page(&self, gfn: Gfn) {
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
    }

    /// Overwrites bytes at `offset` within the page at `gfn`, creating a blank
    /// page first if none exists.
    fn write_original(&self, gfn: Gfn, offset: usize, bytes: &[u8]) {
        let mut pages = self.pages.borrow_mut();
        let page = pages.entry(gfn).or_insert_with(|| vec![0u8; 4096]);
        page[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Writes a page table entry at the given physical address.
    fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        let gfn = Amd64::gfn_from_pa(pa);
        let offset = Amd64::pa_offset(pa) as usize;
        let mut pages = self.pages.borrow_mut();
        let page = pages.get_mut(&gfn).expect("page for pte");
        page[offset..offset + 8].copy_from_slice(&pte.0.to_le_bytes());
    }

    /// Returns the byte at `offset` within the page at `gfn`.
    fn byte(&self, gfn: Gfn, offset: usize) -> u8 {
        self.pages.borrow().get(&gfn).expect("page exists")[offset]
    }

    /// Returns the shadow frame currently mapped for `(view, gfn)`, if any.
    fn view_target(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.views.borrow().get(&(view, gfn)).copied()
    }

    /// Returns the memory access currently configured for `(view, gfn)`,
    /// defaulting to `RWX` when none was set.
    fn access(&self, gfn: Gfn, view: View) -> MemoryAccess {
        self.access
            .borrow()
            .get(&(view, gfn))
            .copied()
            .unwrap_or(MemoryAccess::RWX)
    }

    /// Returns a copy of the recorded operation log.
    fn calls(&self) -> Vec<Call> {
        self.log.borrow().clone()
    }

    /// Clears the recorded operation log.
    fn clear_log(&self) {
        self.log.borrow_mut().clear();
    }

    /// Counts recorded operations matching `predicate`.
    fn count(&self, predicate: impl Fn(&Call) -> bool) -> usize {
        self.log.borrow().iter().filter(|c| predicate(c)).count()
    }

    /// Arms operation `op` to fail on its `nth` (1-based) invocation.
    fn arm_fault(&self, op: Op, nth: usize) {
        self.faults.borrow_mut().insert(op, nth);
    }

    /// Increments the invocation counter for `op` and returns an error if this
    /// invocation is armed to fail.
    fn maybe_fail(&self, op: Op) -> Result<(), VmiError> {
        let mut counters = self.counters.borrow_mut();
        let count = counters.entry(op).or_insert(0);
        *count += 1;
        let count = *count;

        if self.faults.borrow().get(&op) == Some(&count) {
            return Err(VmiError::Other("injected driver fault"));
        }

        Ok(())
    }
}

impl VmiDriver for MockDriver {
    type Architecture = Amd64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: 4096,
            page_shift: 12,
            max_gfn: Gfn(0xFFFF),
            vcpus: 1,
        })
    }
}

impl VmiRead for MockDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.maybe_fail(Op::ReadPage)?;
        self.log.borrow_mut().push(Call::ReadPage(gfn));

        let pages = self.pages.borrow();
        let page = pages.get(&gfn).ok_or(VmiError::Other("read: no page"))?;
        Ok(VmiMappedPage::new(page.clone()))
    }
}

impl VmiWrite for MockDriver {
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        self.maybe_fail(Op::WritePage)?;
        self.log.borrow_mut().push(Call::WritePage {
            gfn,
            offset,
            len: content.len(),
        });

        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&gfn)
            .ok_or(VmiError::Other("write: no page"))?;

        let start = offset as usize;
        let end = start + content.len();
        assert!(end <= page.len(), "write past end of page");
        page[start..end].copy_from_slice(content);

        Ok(VmiMappedPage::new(page.clone()))
    }
}

impl VmiViewControl for MockDriver {
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
        Ok(())
    }

    fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
        Ok(())
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        self.maybe_fail(Op::ChangeView)?;
        self.log.borrow_mut().push(Call::ChangeViewGfn {
            view,
            old: old_gfn,
            new: new_gfn,
        });
        self.views.borrow_mut().insert((view, old_gfn), new_gfn);
        Ok(())
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.maybe_fail(Op::ResetView)?;
        self.log.borrow_mut().push(Call::ResetViewGfn { view, gfn });
        self.views.borrow_mut().remove(&(view, gfn));
        Ok(())
    }
}

impl VmiVmControl for MockDriver {
    fn pause(&self) -> Result<(), VmiError> {
        Ok(())
    }

    fn resume(&self) -> Result<(), VmiError> {
        Ok(())
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        self.maybe_fail(Op::AllocateGfn)?;

        let gfn = Gfn(self.next_gfn.get());
        self.next_gfn.set(gfn.0 + 1);

        // A freshly allocated frame is zeroed and immediately readable/writable.
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
        self.log.borrow_mut().push(Call::AllocateGfn(gfn));
        Ok(gfn)
    }

    fn allocate_gfn_at(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
        Ok(())
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.pages.borrow_mut().remove(&gfn);
        Ok(())
    }

    fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: Interrupt) -> Result<(), VmiError> {
        Ok(())
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Ok(())
    }
}

impl VmiQueryProtection for MockDriver {
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.access(gfn, view))
    }

    fn memory_access_with_options(
        &self,
        _gfn: Gfn,
        _view: View,
    ) -> Result<(MemoryAccess, MemoryAccessOptions), VmiError> {
        Err(VmiError::NotSupported)
    }
}

impl VmiSetProtection for MockDriver {
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        self.maybe_fail(Op::SetMemoryAccess)?;
        self.log
            .borrow_mut()
            .push(Call::SetMemoryAccess { gfn, view, access });
        self.access.borrow_mut().insert((view, gfn), access);
        Ok(())
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        _options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        self.set_memory_access(gfn, view, access)
    }
}

///////////////////////////////////////////////////////////////////////////////
// Recording Controller
///////////////////////////////////////////////////////////////////////////////

/// A single controller operation the `BreakpointManager` requested, used to
/// assert the manager's orchestration independent of any concrete controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControllerCall {
    /// `insert_breakpoint(pa, view)`.
    Insert { pa: Pa, view: View },

    /// `remove_breakpoint(pa, view)`.
    Remove { pa: Pa, view: View },

    /// `monitor(gfn, view)`.
    Monitor { gfn: Gfn, view: View },

    /// `unmonitor(gfn, view)`.
    Unmonitor { gfn: Gfn, view: View },
}

/// A controller operation that can be armed to fail on a chosen invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ControllerOp {
    /// `insert_breakpoint`.
    Insert,

    /// `remove_breakpoint`.
    Remove,

    /// `monitor`.
    Monitor,

    /// `unmonitor`.
    Unmonitor,
}

/// The error kind an armed controller fault produces.
#[derive(Clone, Copy, Debug)]
enum FaultKind {
    /// A generic error that propagates unchanged.
    Other,

    /// `ViewNotFound`, which the manager tolerates during removal.
    ViewNotFound,
}

thread_local! {
    /// Ordered log of controller operations for the current test thread.
    static REC_LOG: RefCell<Vec<ControllerCall>> = const { RefCell::new(Vec::new()) };

    /// Per-operation invocation counters for the current test thread.
    static REC_COUNTERS: RefCell<HashMap<ControllerOp, usize>> = RefCell::new(HashMap::new());

    /// Armed controller faults for the current test thread, mapping an
    /// operation to the 1-based invocation to fail and the error to produce.
    static REC_FAULTS: RefCell<HashMap<ControllerOp, (usize, FaultKind)>> =
        RefCell::new(HashMap::new());
}

/// Clears all recorded controller state for the current test thread.
fn rec_reset() {
    REC_LOG.with(|l| l.borrow_mut().clear());
    REC_COUNTERS.with(|c| c.borrow_mut().clear());
    REC_FAULTS.with(|f| f.borrow_mut().clear());
}

/// Returns a copy of the recorded controller operations.
fn rec_calls() -> Vec<ControllerCall> {
    REC_LOG.with(|l| l.borrow().clone())
}

/// Clears the recorded controller operation log, keeping counters and faults.
fn rec_clear_log() {
    REC_LOG.with(|l| l.borrow_mut().clear());
}

/// Counts recorded controller operations matching `predicate`.
fn rec_count(predicate: impl Fn(&ControllerCall) -> bool) -> usize {
    REC_LOG.with(|l| l.borrow().iter().filter(|c| predicate(c)).count())
}

/// Arms controller operation `op` to fail on its `nth` invocation with `kind`.
fn rec_arm_fault(op: ControllerOp, nth: usize, kind: FaultKind) {
    REC_FAULTS.with(|f| f.borrow_mut().insert(op, (nth, kind)));
}

/// Records `call` in the current thread's controller log.
fn rec_push(call: ControllerCall) {
    REC_LOG.with(|l| l.borrow_mut().push(call));
}

/// Increments the invocation counter for `op` and returns an error if this
/// invocation is armed to fail.
fn rec_maybe_fail(op: ControllerOp) -> Result<(), VmiError> {
    let count = REC_COUNTERS.with(|c| {
        let mut counters = c.borrow_mut();
        let count = counters.entry(op).or_insert(0);
        *count += 1;
        *count
    });

    let fault = REC_FAULTS.with(|f| f.borrow().get(&op).copied());
    match fault {
        Some((nth, kind)) if nth == count => match kind {
            FaultKind::Other => Err(VmiError::Other("injected controller fault")),
            FaultKind::ViewNotFound => Err(VmiError::ViewNotFound),
        },
        _ => Ok(()),
    }
}

/// A `TapController` that records the manager's requests into thread-local state
/// instead of touching any driver.
///
/// The manager constructs its controller internally through
/// [`BreakpointManager::new`], so the recorder lives in thread-local storage
/// that [`TapController::new`] resets on construction. Each test creates exactly
/// one manager, giving it a clean recording slate.
struct RecordingController {
    _marker: PhantomData<MockDriver>,
}

impl TapController for RecordingController {
    type Driver = MockDriver;

    fn new() -> Self {
        rec_reset();
        Self {
            _marker: PhantomData,
        }
    }

    fn check_event(&self, event: &VmiEvent<Amd64>) -> Option<(View, Gfn)> {
        let interrupt = event.reason().as_software_breakpoint()?;
        let view = event.view()?;
        Some((view, interrupt.gfn()))
    }

    fn insert_breakpoint(
        &mut self,
        _vmi: &VmiCore<MockDriver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        rec_maybe_fail(ControllerOp::Insert)?;
        rec_push(ControllerCall::Insert { pa, view });
        Ok(())
    }

    fn remove_breakpoint(
        &mut self,
        _vmi: &VmiCore<MockDriver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        rec_maybe_fail(ControllerOp::Remove)?;
        rec_push(ControllerCall::Remove { pa, view });
        Ok(())
    }

    fn monitor(
        &mut self,
        _vmi: &VmiCore<MockDriver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        rec_maybe_fail(ControllerOp::Monitor)?;
        rec_push(ControllerCall::Monitor { gfn, view });
        Ok(())
    }

    fn unmonitor(
        &mut self,
        _vmi: &VmiCore<MockDriver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        rec_maybe_fail(ControllerOp::Unmonitor)?;
        rec_push(ControllerCall::Unmonitor { gfn, view });
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
// Test Helpers
///////////////////////////////////////////////////////////////////////////////

/// A manager driven by the recording controller with unit key and string tag.
type RecManager = BreakpointManager<RecordingController>;

/// Primary view used by most tests.
const VIEW: View = View(0);

/// Secondary view used by multi-view tests.
const VIEW2: View = View(3);

/// Guest code page a breakpoint is installed into.
const CODE_GFN: Gfn = Gfn(0x10);

/// A second, unrelated guest code page.
const OTHER_GFN: Gfn = Gfn(0x11);

/// First translation root (page-aligned so it survives CR3 PFN masking).
const ROOT1: Pa = Pa(0x2000);

/// Second translation root.
const ROOT2: Pa = Pa(0x3000);

/// Page-aligned virtual base. The low 12 bits carry the in-page offset, which
/// must match the physical offset for event-based lookups to reconstruct the
/// same physical address.
const VA_BASE: u64 = 0xffff_f800_0004_0000;

/// Primary in-page offset used for breakpoints.
const OFFSET: u64 = 0x100;

/// Secondary in-page offset.
const OFFSET2: u64 = 0x200;

/// vCPU used for synthesized events.
const VCPU: VcpuId = VcpuId(0);

/// Returns the physical address of `offset` within the page at `gfn`.
fn pa_at(gfn: Gfn, offset: u64) -> Pa {
    Amd64::pa_from_gfn(gfn) + offset
}

/// Returns the canonical virtual address carrying `offset`.
fn va_at(offset: u64) -> Va {
    Va(VA_BASE | offset)
}

/// Builds an address context for `offset` under translation root `root`.
fn ctx_at(offset: u64, root: Pa) -> AddressContext {
    AddressContext::new(va_at(offset), root)
}

/// Builds a plain (non-global) unit-key string-tag breakpoint. Returns a
/// `Breakpoint` value (which is `Copy`) so a single definition can be reused.
fn bp(offset: u64, root: Pa, view: View) -> Breakpoint<(), &'static str> {
    Breakpoint::new(ctx_at(offset, root), view).into()
}

/// Builds a global unit-key string-tag breakpoint.
fn bp_global(offset: u64, root: Pa, view: View) -> Breakpoint<(), &'static str> {
    Breakpoint::new(ctx_at(offset, root), view).global().into()
}

/// Wraps a driver in a `VmiCore` with the page and translation caches disabled.
fn make_vmi(driver: MockDriver) -> Result<VmiCore<MockDriver>, VmiError> {
    let mut vmi = VmiCore::new(driver)?;
    vmi.disable_gfn_cache();
    vmi.disable_v2p_cache();
    Ok(vmi)
}

/// Builds a software-breakpoint event whose faulting page is `gfn`, whose
/// instruction pointer is `va`, and whose translation root is `root`.
fn bp_event(view: Option<View>, gfn: Gfn, va: Va, root: Pa) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: va.0,
        cr3: Cr3(root.0),
        ..Default::default()
    };
    let reason = EventReason::Interrupt(EventInterrupt {
        gfn,
        interrupt: Interrupt::breakpoint(1),
    });
    VmiEvent::new(VCPU, VmiEventFlags::empty(), view, registers, reason)
}

/// Builds a singlestep event, which is never a software breakpoint.
fn singlestep_event(view: Option<View>, gfn: Gfn, va: Va) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: va.0,
        ..Default::default()
    };
    let reason = EventReason::Singlestep(EventSinglestep { gfn });
    VmiEvent::new(VCPU, VmiEventFlags::empty(), view, registers, reason)
}

/// Builds a memory-access event carrying `access` at `(gfn, va)`.
fn mem_event(view: Option<View>, gfn: Gfn, va: Va, access: MemoryAccess) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: va.0,
        ..Default::default()
    };
    let reason = EventReason::MemoryAccess(EventMemoryAccess {
        pa: pa_at(gfn, Amd64::va_offset(va)),
        va,
        access,
        flags: MemoryAccessFlags::empty(),
    });
    VmiEvent::new(VCPU, VmiEventFlags::empty(), view, registers, reason)
}

/// Builds a full PML4 -> PDPT -> PD -> PT -> data translation for `va` rooted at
/// `pml4_gfn`, using the three frames above `pml4_gfn` as intermediate tables.
fn map_translation(driver: &MockDriver, pml4_gfn: Gfn, va: Va, data_gfn: Gfn) {
    let pdpt = Gfn(pml4_gfn.0 + 1);
    let pd = Gfn(pml4_gfn.0 + 2);
    let pt = Gfn(pml4_gfn.0 + 3);

    for gfn in [pml4_gfn, pdpt, pd, pt, data_gfn] {
        driver.insert_page(gfn);
    }

    let pte = |gfn: Gfn| PageTableEntry((gfn.0 << 12) | 1);
    driver.write_pte(
        pa_at(pml4_gfn, Amd64::va_index_for(va, PageTableLevel::Pml4) * 8),
        pte(pdpt),
    );
    driver.write_pte(
        pa_at(pdpt, Amd64::va_index_for(va, PageTableLevel::Pdpt) * 8),
        pte(pd),
    );
    driver.write_pte(
        pa_at(pd, Amd64::va_index_for(va, PageTableLevel::Pd) * 8),
        pte(pt),
    );
    driver.write_pte(
        pa_at(pt, Amd64::va_index_for(va, PageTableLevel::Pt) * 8),
        pte(data_gfn),
    );
}

/// Convenience predicate: any `Insert` controller call.
fn is_insert(call: &ControllerCall) -> bool {
    matches!(call, ControllerCall::Insert { .. })
}

/// Convenience predicate: any `Remove` controller call.
fn is_remove(call: &ControllerCall) -> bool {
    matches!(call, ControllerCall::Remove { .. })
}

/// Convenience predicate: any `Monitor` controller call.
fn is_monitor(call: &ControllerCall) -> bool {
    matches!(call, ControllerCall::Monitor { .. })
}

/// Convenience predicate: any `Unmonitor` controller call.
fn is_unmonitor(call: &ControllerCall) -> bool {
    matches!(call, ControllerCall::Unmonitor { .. })
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Active (with hint)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_active_installs_then_monitors() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    let inserted =
        manager.insert_with_hint(&vmi, Breakpoint::new(ctx_at(OFFSET, ROOT1), VIEW), Some(pa))?;

    // A fresh active breakpoint is installed first, then the page is monitored.
    assert!(inserted);
    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Insert { pa, view: VIEW },
            ControllerCall::Monitor {
                gfn: CODE_GFN,
                view: VIEW,
            },
        ]
    );

    Ok(())
}

#[test]
fn duplicate_active_insert_returns_false_without_calls() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    let breakpoint = bp(OFFSET, ROOT1, VIEW);
    manager.insert_with_hint(&vmi, breakpoint, Some(pa))?;
    rec_clear_log();

    // Re-inserting the same breakpoint is a no-op returning false.
    let inserted = manager.insert_with_hint(&vmi, breakpoint, Some(pa))?;
    assert!(!inserted);
    assert!(rec_calls().is_empty());

    Ok(())
}

#[test]
fn two_breakpoints_same_page_insert_twice_monitor_once() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx_at(OFFSET, ROOT1), VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;
    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx_at(OFFSET2, ROOT1), VIEW),
        Some(pa_at(CODE_GFN, OFFSET2)),
    )?;

    // Two distinct sites on the same page: two installs, one monitor.
    assert_eq!(rec_count(is_insert), 2);
    assert_eq!(rec_count(is_monitor), 1);

    Ok(())
}

#[test]
fn two_breakpoints_different_pages_monitor_each() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx_at(OFFSET, ROOT1), VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;
    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx_at(OFFSET, ROOT1), VIEW),
        Some(pa_at(OTHER_GFN, OFFSET)),
    )?;

    assert_eq!(rec_count(is_insert), 2);
    assert_eq!(rec_count(is_monitor), 2);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Pending
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_pending_records_no_controller_calls() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let inserted = manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), None)?;

    // A pending breakpoint touches no controller and is not "active".
    assert!(inserted);
    assert!(rec_calls().is_empty());
    assert!(!manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn duplicate_pending_insert_returns_false() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let breakpoint = bp(OFFSET, ROOT1, VIEW);
    assert!(manager.insert_with_hint(&vmi, breakpoint, None)?);
    assert!(!manager.insert_with_hint(&vmi, breakpoint, None)?);

    Ok(())
}

#[test]
fn pending_same_ctx_different_tag_are_distinct() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    // Pending breakpoints are deduplicated by their whole definition, so a new
    // tag at the same context is a distinct pending entry.
    assert!(manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_tag("a"), None)?);
    assert!(manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_tag("b"), None)?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Tags and shared physical pages
///////////////////////////////////////////////////////////////////////////////

#[test]
fn active_same_ctx_different_tag_returns_false_but_is_recorded() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    assert!(manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_tag("a"), Some(pa))?);
    rec_clear_log();

    // A second tag at the same (key, context) is not a new install, but it is
    // retained alongside the first, as `get_by_event` shows.
    assert!(!manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_tag("b"), Some(pa))?);
    assert!(rec_calls().is_empty());

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    let tags = manager
        .get_by_event(&event, ())
        .expect("breakpoints")
        .count();
    assert_eq!(tags, 2);

    Ok(())
}

#[test]
fn shared_physical_page_two_contexts_install_twice_monitor_once() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // Same VA in two processes (roots) backed by one physical page.
    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT2, VIEW), Some(pa))?;

    // One shared page: two installs, one monitor.
    assert_eq!(rec_count(is_insert), 2);
    assert_eq!(rec_count(is_monitor), 1);

    // Removing one context keeps the page monitored for the other.
    rec_clear_log();
    manager.remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    assert_eq!(rec_count(is_remove), 1);
    assert_eq!(rec_count(is_unmonitor), 0);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert / Remove: Translation dispatch
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_translates_and_activates_when_mapped() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    let pml4 = Gfn(0x40);
    let data = Gfn(0x50);
    let va = Va(0x1_0100);
    map_translation(&driver, pml4, va, data);

    let vmi = make_vmi(driver)?;
    let mut manager = RecManager::new();

    let root = Amd64::pa_from_gfn(pml4);
    let inserted = manager.insert(&vmi, Breakpoint::new(AddressContext::new(va, root), VIEW))?;

    assert!(inserted);
    let expected_pa = pa_at(data, Amd64::va_offset(va));
    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Insert {
                pa: expected_pa,
                view: VIEW,
            },
            ControllerCall::Monitor {
                gfn: data,
                view: VIEW
            },
        ]
    );

    Ok(())
}

#[test]
fn insert_registers_pending_when_translation_absent() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    let pml4 = Gfn(0x40);
    // A present but empty PML4 makes the walk stop at a not-present entry, which
    // surfaces as a translation error rather than a read failure.
    driver.insert_page(pml4);

    let vmi = make_vmi(driver)?;
    let mut manager = RecManager::new();

    let va = Va(0x1_0100);
    let ctx = AddressContext::new(va, Amd64::pa_from_gfn(pml4));
    let inserted = manager.insert(&vmi, Breakpoint::new(ctx, VIEW))?;

    assert!(inserted);
    assert!(rec_calls().is_empty());
    assert!(!manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn insert_propagates_non_translation_error() -> Result<(), VmiError> {
    // No page backs the root at all, so the page-table read fails outright.
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = AddressContext::new(Va(0x1_0100), Amd64::pa_from_gfn(Gfn(0x40)));
    assert!(manager.insert(&vmi, Breakpoint::new(ctx, VIEW)).is_err());

    Ok(())
}

#[test]
fn remove_translates_and_removes_when_mapped() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    let pml4 = Gfn(0x40);
    let data = Gfn(0x50);
    let va = Va(0x1_0100);
    map_translation(&driver, pml4, va, data);

    let vmi = make_vmi(driver)?;
    let mut manager = RecManager::new();

    let ctx = AddressContext::new(va, Amd64::pa_from_gfn(pml4));
    manager.insert(&vmi, Breakpoint::new(ctx, VIEW))?;

    assert!(manager.remove(&vmi, Breakpoint::new(ctx, VIEW))?);
    assert!(!manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn remove_without_translation_removes_pending() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    let pml4 = Gfn(0x40);
    driver.insert_page(pml4);

    let vmi = make_vmi(driver)?;
    let mut manager = RecManager::new();

    let ctx = AddressContext::new(Va(0x1_0100), Amd64::pa_from_gfn(pml4));
    manager.insert(&vmi, Breakpoint::new(ctx, VIEW))?;

    // The pending breakpoint is removed even though the address is unmapped.
    assert!(manager.remove(&vmi, Breakpoint::new(ctx, VIEW))?);
    // A second removal finds nothing.
    assert!(!manager.remove(&vmi, Breakpoint::new(ctx, VIEW))?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Remove (with hint)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_active_last_removes_then_unmonitors() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    rec_clear_log();

    assert!(manager.remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?);
    // The breakpoint is removed first, then the now-empty page is unmonitored.
    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Remove { pa, view: VIEW },
            ControllerCall::Unmonitor {
                gfn: CODE_GFN,
                view: VIEW,
            },
        ]
    );

    Ok(())
}

#[test]
fn remove_pending_returns_true_without_calls() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?;
    rec_clear_log();

    assert!(manager.remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?);
    assert!(rec_calls().is_empty());

    Ok(())
}

#[test]
fn activating_a_pending_breakpoint_drops_the_pending_copy() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    // Register the breakpoint as pending, then activate the same breakpoint.
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), None)?;
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), Some(pa))?;
    rec_clear_log();

    // Removal now tears down the active copy instead of stopping at a stale
    // pending copy and leaking the installed breakpoint.
    assert!(manager.remove_with_hint(&vmi, Breakpoint::new(ctx, VIEW), Some(pa))?);
    assert_eq!(rec_count(is_remove), 1);
    assert!(!manager.contains_by_address(ctx, ()));
    // No stray pending copy remains either.
    assert!(manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), None)?);

    Ok(())
}

#[test]
fn remove_unknown_returns_false() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    assert!(!manager.remove_with_hint(
        &vmi,
        bp(OFFSET, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET))
    )?);
    assert!(rec_calls().is_empty());

    Ok(())
}

#[test]
fn remove_absent_context_on_populated_page_returns_false() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // One breakpoint occupies the page.
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;

    // A different context on the same page was never installed: removal reports
    // that nothing was found rather than a spurious success.
    assert!(!manager.remove_with_hint(
        &vmi,
        bp(OFFSET2, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET2))
    )?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// remove_by_event
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_by_event_last_returns_some_true() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    rec_clear_log();

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, Some(true));
    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Remove { pa, view: VIEW },
            ControllerCall::Unmonitor {
                gfn: CODE_GFN,
                view: VIEW,
            },
        ]
    );

    Ok(())
}

#[test]
fn remove_by_event_not_last_returns_some_false() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT2, VIEW), Some(pa))?;
    rec_clear_log();

    // The event resolves to the ROOT1 context; the ROOT2 context still holds a
    // breakpoint on the page.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, Some(false));
    assert_eq!(rec_count(is_remove), 1);
    assert_eq!(rec_count(is_unmonitor), 0);

    Ok(())
}

#[test]
fn remove_by_event_unmatched_returns_none() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // Nothing is installed, so a well-formed event finds no breakpoint.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, None);

    // An event without a view cannot resolve either.
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;
    let event = bp_event(None, CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, None);

    Ok(())
}

#[test]
fn remove_by_event_removes_across_views() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // The same key and context installed in two views.
    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW2), Some(pa))?;
    rec_clear_log();

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, Some(true));
    // Both views are cleared for this context.
    assert_eq!(rec_count(is_remove), 2);
    assert_eq!(rec_count(is_unmonitor), 2);
    assert!(!manager.contains_by_address(ctx_at(OFFSET, ROOT1), ()));

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// remove_by_view
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_by_view_removes_only_target_view() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;
    manager.insert_with_hint(
        &vmi,
        bp(OFFSET2, ROOT1, VIEW2),
        Some(pa_at(CODE_GFN, OFFSET2)),
    )?;
    rec_clear_log();

    assert!(manager.remove_by_view(&vmi, VIEW)?);
    assert_eq!(rec_count(is_remove), 1);
    assert_eq!(rec_count(is_unmonitor), 1);
    assert!(!manager.contains_by_address(ctx_at(OFFSET, ROOT1), ()));
    assert!(manager.contains_by_address(ctx_at(OFFSET2, ROOT1), ()));

    Ok(())
}

#[test]
fn remove_by_view_empty_returns_false() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    assert!(!manager.remove_by_view(&vmi, VIEW)?);

    Ok(())
}

#[test]
fn remove_by_view_with_only_pending_returns_true() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // The view holds only a pending breakpoint, no active one.
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?;

    // A pending breakpoint was removed, so the call reports true.
    assert!(manager.remove_by_view(&vmi, VIEW)?);
    // The pending breakpoint is gone: re-inserting it reports a fresh entry.
    assert!(manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?);

    Ok(())
}

#[test]
fn remove_by_view_also_clears_pending() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;
    manager.insert_with_hint(&vmi, bp(OFFSET2, ROOT1, VIEW), None)?;

    assert!(manager.remove_by_view(&vmi, VIEW)?);

    // The pending breakpoint was cleared: re-inserting it reports a new entry.
    assert!(manager.insert_with_hint(&vmi, bp(OFFSET2, ROOT1, VIEW), None)?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-in / Page-out
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_in_activates_pending_breakpoint() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), None)?;
    rec_clear_log();

    let pa = pa_at(CODE_GFN, OFFSET);
    let update = PageEntryUpdate {
        view: VIEW,
        ctx,
        pa,
    };
    assert!(manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageIn(update))?);

    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Insert { pa, view: VIEW },
            ControllerCall::Monitor {
                gfn: CODE_GFN,
                view: VIEW,
            },
        ]
    );
    assert!(manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn page_in_without_pending_reports_no_change() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let update = PageEntryUpdate {
        view: VIEW,
        ctx: ctx_at(OFFSET, ROOT1),
        pa: pa_at(CODE_GFN, OFFSET),
    };
    assert!(!manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageIn(update))?);
    assert!(rec_calls().is_empty());

    Ok(())
}

#[test]
fn page_out_moves_active_to_pending() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), Some(pa))?;
    rec_clear_log();

    let update = PageEntryUpdate {
        view: VIEW,
        ctx,
        pa,
    };
    assert!(manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageOut(update))?);

    assert_eq!(
        rec_calls(),
        vec![
            ControllerCall::Remove { pa, view: VIEW },
            ControllerCall::Unmonitor {
                gfn: CODE_GFN,
                view: VIEW,
            },
        ]
    );
    // The breakpoint is no longer active, but it is retained as pending.
    assert!(!manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn page_out_without_active_reports_no_change() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let update = PageEntryUpdate {
        view: VIEW,
        ctx: ctx_at(OFFSET, ROOT1),
        pa: pa_at(CODE_GFN, OFFSET),
    };
    assert!(!manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageOut(update))?);

    Ok(())
}

#[test]
fn page_out_then_page_in_round_trip() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW), Some(pa))?;

    let update = PageEntryUpdate {
        view: VIEW,
        ctx,
        pa,
    };
    manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageOut(update))?;
    assert!(!manager.contains_by_address(ctx, ()));

    manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageIn(update))?;
    assert!(manager.contains_by_address(ctx, ()));

    Ok(())
}

#[test]
fn handle_ptm_events_processes_batch() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx_a = ctx_at(OFFSET, ROOT1);
    let ctx_b = ctx_at(OFFSET2, ROOT1);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx_a, VIEW), None)?;
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx_b, VIEW), None)?;
    rec_clear_log();

    let events = vec![
        PageTableMonitorEvent::PageIn(PageEntryUpdate {
            view: VIEW,
            ctx: ctx_a,
            pa: pa_at(CODE_GFN, OFFSET),
        }),
        PageTableMonitorEvent::PageIn(PageEntryUpdate {
            view: VIEW,
            ctx: ctx_b,
            pa: pa_at(CODE_GFN, OFFSET2),
        }),
    ];
    assert!(manager.handle_ptm_events(&vmi, events)?);
    assert_eq!(rec_count(is_insert), 2);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// clear
///////////////////////////////////////////////////////////////////////////////

#[test]
fn clear_removes_all_active_breakpoints() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;
    manager.insert_with_hint(
        &vmi,
        bp(OFFSET, ROOT1, VIEW),
        Some(pa_at(OTHER_GFN, OFFSET)),
    )?;
    rec_clear_log();

    manager.clear(&vmi)?;
    assert_eq!(rec_count(is_remove), 2);
    assert_eq!(rec_count(is_unmonitor), 2);
    assert!(!manager.contains_by_address(ctx_at(OFFSET, ROOT1), ()));

    // The manager is usable again after clearing.
    assert!(manager.insert_with_hint(
        &vmi,
        bp(OFFSET, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET))
    )?);

    Ok(())
}

#[test]
fn clear_on_empty_manager_is_ok() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.clear(&vmi)?;
    assert!(rec_calls().is_empty());

    Ok(())
}

#[test]
fn clear_after_pending_insert_does_not_panic() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // A pending breakpoint populates the per-view pending index, which clear()
    // must also drain to keep its internal maps consistent.
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?;
    manager.clear(&vmi)?;

    // The pending breakpoint is gone: re-inserting it reports a fresh entry.
    assert!(manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), None)?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// contains / get_by_event
///////////////////////////////////////////////////////////////////////////////

#[test]
fn contains_by_event_distinguishes_installed_breakpoints() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;

    assert!(manager.contains_by_event(&bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1), ()));
    // Different page.
    assert!(!manager.contains_by_event(&bp_event(Some(VIEW), OTHER_GFN, va_at(OFFSET), ROOT1), ()));
    // Not a software breakpoint.
    assert!(!manager.contains_by_event(&singlestep_event(Some(VIEW), CODE_GFN, va_at(OFFSET)), ()));

    Ok(())
}

#[test]
fn contains_by_address_is_active_only() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let active = ctx_at(OFFSET, ROOT1);
    let pending = ctx_at(OFFSET2, ROOT1);
    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(active, VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;
    manager.insert_with_hint(&vmi, Breakpoint::new(pending, VIEW), None)?;

    assert!(manager.contains_by_address(active, ()));
    assert!(!manager.contains_by_address(pending, ()));

    Ok(())
}

#[test]
fn get_by_event_returns_matching_breakpoints() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    let breakpoints = manager.get_by_event(&event, ()).expect("breakpoints");
    assert_eq!(breakpoints.count(), 1);

    Ok(())
}

#[test]
fn get_by_event_none_when_unmatched() {
    let manager = RecManager::new();

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert!(manager.get_by_event(&event, ()).is_none());
}

///////////////////////////////////////////////////////////////////////////////
// Keys
///////////////////////////////////////////////////////////////////////////////

#[test]
fn different_keys_are_independent() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = BreakpointManager::<RecordingController, u32>::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(1u32), Some(pa))?;
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(2u32), Some(pa))?;

    assert!(manager.contains_by_address(ctx, 1u32));
    assert!(manager.contains_by_address(ctx, 2u32));

    // Removing one key leaves the other installed.
    manager.remove_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(1u32), Some(pa))?;
    assert!(!manager.contains_by_address(ctx, 1u32));
    assert!(manager.contains_by_address(ctx, 2u32));

    Ok(())
}

#[test]
fn remove_pending_only_affects_requested_key() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = BreakpointManager::<RecordingController, u32>::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(1u32), None)?;
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(2u32), None)?;

    // Removing one key's pending breakpoint leaves another key's intact.
    assert!(manager.remove_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(1u32), None)?);
    // Key 2 is still pending: re-inserting reports it already exists.
    assert!(!manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(2u32), None)?);
    // Key 1 is gone: re-inserting reports a fresh entry.
    assert!(manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_key(1u32), None)?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Global breakpoints
///////////////////////////////////////////////////////////////////////////////

#[test]
fn global_breakpoint_matches_any_root() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(
        &vmi,
        bp_global(OFFSET, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;

    // A different translation root still matches a global breakpoint.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT2);
    assert!(manager.contains_by_event(&event, ()));

    Ok(())
}

#[test]
fn non_global_breakpoint_requires_matching_root() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))?;

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT2);
    assert!(!manager.contains_by_event(&event, ()));

    Ok(())
}

#[test]
fn global_breakpoint_spans_pages_and_remove_by_event_clears_all() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // The same global VA in two roots resolves to two different physical pages.
    manager.insert_with_hint(
        &vmi,
        bp_global(OFFSET, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;
    manager.insert_with_hint(
        &vmi,
        bp_global(OFFSET, ROOT2, VIEW),
        Some(pa_at(OTHER_GFN, OFFSET)),
    )?;
    assert_eq!(rec_count(is_insert), 2);
    assert_eq!(rec_count(is_monitor), 2);
    rec_clear_log();

    // Removing by an event on one page tears down both pages of the global.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(manager.remove_by_event(&vmi, &event, ())?, Some(true));
    assert_eq!(rec_count(is_remove), 2);
    assert_eq!(rec_count(is_unmonitor), 2);
    assert!(!manager.contains_by_address(ctx_at(OFFSET, ROOT1), ()));

    Ok(())
}

#[test]
fn global_breakpoint_duplicate_insert_is_idempotent() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    assert!(manager.insert_with_hint(&vmi, bp_global(OFFSET, ROOT1, VIEW), Some(pa))?);
    // A second identical global insert is a no-op, not a panic.
    assert!(!manager.insert_with_hint(&vmi, bp_global(OFFSET, ROOT1, VIEW), Some(pa))?);
    assert_eq!(rec_count(is_insert), 1);

    Ok(())
}

#[test]
fn global_breakpoint_second_root_same_page_is_idempotent() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // Two roots that map the same VA to the same physical page collapse onto a
    // single global breakpoint.
    let pa = pa_at(CODE_GFN, OFFSET);
    assert!(manager.insert_with_hint(&vmi, bp_global(OFFSET, ROOT1, VIEW), Some(pa))?);
    assert!(!manager.insert_with_hint(&vmi, bp_global(OFFSET, ROOT2, VIEW), Some(pa))?);
    assert_eq!(rec_count(is_insert), 1);

    Ok(())
}

#[test]
fn global_breakpoints_with_distinct_keys_share_a_page() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = BreakpointManager::<RecordingController, u32>::new();

    // Two owners install a global breakpoint at the same VA on the same page.
    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    assert!(manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx, VIEW).global().with_key(1u32),
        Some(pa)
    )?);
    assert!(manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx, VIEW).global().with_key(2u32),
        Some(pa)
    )?);

    // Removing one owner keeps the global breakpoint matching for the other.
    manager.remove_with_hint(
        &vmi,
        Breakpoint::new(ctx, VIEW).global().with_key(1u32),
        Some(pa),
    )?;
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT2);
    assert!(manager.contains_by_event(&event, 2u32));
    assert!(!manager.contains_by_event(&event, 1u32));

    // Removing the second owner tears the page down and stops matching.
    manager.remove_with_hint(
        &vmi,
        Breakpoint::new(ctx, VIEW).global().with_key(2u32),
        Some(pa),
    )?;
    assert!(!manager.contains_by_event(&event, 2u32));

    Ok(())
}

#[test]
fn removing_nonglobal_leaves_global_at_same_va_intact() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    // A global breakpoint and a non-global breakpoint share a VA but sit on
    // different physical pages.
    manager.insert_with_hint(
        &vmi,
        bp_global(OFFSET, ROOT1, VIEW),
        Some(pa_at(CODE_GFN, OFFSET)),
    )?;
    manager.insert_with_hint(
        &vmi,
        bp(OFFSET, ROOT2, VIEW),
        Some(pa_at(OTHER_GFN, OFFSET)),
    )?;

    // Removing the non-global one must not disturb the global bookkeeping.
    assert!(manager.remove_with_hint(
        &vmi,
        bp(OFFSET, ROOT2, VIEW),
        Some(pa_at(OTHER_GFN, OFFSET))
    )?);

    // The global breakpoint still matches regardless of root.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT2);
    assert!(manager.contains_by_event(&event, ()));

    Ok(())
}

#[test]
fn global_breakpoint_added_onto_existing_context_matches_any_root() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let ctx = ctx_at(OFFSET, ROOT1);
    let pa = pa_at(CODE_GFN, OFFSET);
    // A non-global breakpoint occupies the (key, context) bucket first.
    manager.insert_with_hint(&vmi, Breakpoint::new(ctx, VIEW).with_tag("a"), Some(pa))?;
    // A global breakpoint at the same (key, context) is added onto that bucket.
    manager.insert_with_hint(
        &vmi,
        Breakpoint::new(ctx, VIEW).global().with_tag("b"),
        Some(pa),
    )?;

    // The global breakpoint must still match regardless of root.
    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT2);
    assert!(manager.contains_by_event(&event, ()));

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Error propagation and ViewNotFound tolerance
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_propagates_controller_install_error() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    rec_arm_fault(ControllerOp::Insert, 1, FaultKind::Other);
    assert!(
        manager
            .insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))
            .is_err()
    );

    Ok(())
}

#[test]
fn insert_propagates_monitor_error() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    rec_arm_fault(ControllerOp::Monitor, 1, FaultKind::Other);
    assert!(
        manager
            .insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa_at(CODE_GFN, OFFSET)))
            .is_err()
    );

    Ok(())
}

#[test]
fn remove_tolerates_view_not_found_on_unmonitor() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;

    // A destroyed view surfaces as ViewNotFound during unmonitor, which removal
    // treats as success.
    rec_arm_fault(ControllerOp::Unmonitor, 1, FaultKind::ViewNotFound);
    assert!(manager.remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?);

    Ok(())
}

#[test]
fn remove_tolerates_view_not_found_on_uninstall() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;

    rec_arm_fault(ControllerOp::Remove, 1, FaultKind::ViewNotFound);
    assert!(manager.remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?);

    Ok(())
}

#[test]
fn remove_propagates_other_error_from_uninstall() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut manager = RecManager::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;

    rec_arm_fault(ControllerOp::Remove, 1, FaultKind::Other);
    assert!(
        manager
            .remove_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))
            .is_err()
    );

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// BreakpointController
///////////////////////////////////////////////////////////////////////////////

#[test]
fn breakpoint_controller_check_event_maps_software_breakpoint() -> Result<(), VmiError> {
    let controller = BreakpointController::<MockDriver>::new();

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert_eq!(controller.check_event(&event), Some((VIEW, CODE_GFN)));

    Ok(())
}

#[test]
fn breakpoint_controller_check_event_rejects_non_breakpoint_and_viewless() {
    let controller = BreakpointController::<MockDriver>::new();

    assert_eq!(
        controller.check_event(&singlestep_event(Some(VIEW), CODE_GFN, va_at(OFFSET))),
        None
    );
    assert_eq!(
        controller.check_event(&bp_event(None, CODE_GFN, va_at(OFFSET), ROOT1)),
        None
    );
}

#[test]
fn breakpoint_controller_insert_creates_shadow_breakpoint() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut controller = BreakpointController::<MockDriver>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    controller.insert_breakpoint(&vmi, pa, VIEW)?;

    let shadow = vmi.driver().view_target(VIEW, CODE_GFN).expect("remapped");
    assert_ne!(shadow, CODE_GFN);
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    assert_eq!(vmi.driver().byte(CODE_GFN, OFFSET as usize), 0xab);

    Ok(())
}

#[test]
fn breakpoint_controller_remove_restores_and_resets_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut controller = BreakpointController::<MockDriver>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    let shadow = vmi.driver().view_target(VIEW, CODE_GFN).expect("remapped");

    controller.remove_breakpoint(&vmi, pa, VIEW)?;
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xab);

    Ok(())
}

#[test]
fn breakpoint_controller_monitor_sets_execute_only() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut controller = BreakpointController::<MockDriver>::new();

    controller.monitor(&vmi, CODE_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(CODE_GFN, VIEW), MemoryAccess::X);

    Ok(())
}

#[test]
fn breakpoint_controller_unmonitor_restores_rwx() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut controller = BreakpointController::<MockDriver>::new();

    controller.monitor(&vmi, CODE_GFN, VIEW)?;
    controller.unmonitor(&vmi, CODE_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(CODE_GFN, VIEW), MemoryAccess::RWX);

    Ok(())
}

#[test]
fn breakpoint_controller_insert_then_monitor_issue_expected_driver_calls() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut controller = BreakpointController::<MockDriver>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    // Inserting a breakpoint remaps the view but never changes protections.
    assert_eq!(
        vmi.driver()
            .count(|c| matches!(c, Call::ChangeViewGfn { .. })),
        1
    );
    assert_eq!(
        vmi.driver()
            .count(|c| matches!(c, Call::SetMemoryAccess { .. })),
        0
    );

    vmi.driver().clear_log();
    controller.monitor(&vmi, CODE_GFN, VIEW)?;
    // Monitoring only changes protection, to execute-only.
    assert_eq!(
        vmi.driver().count(|c| matches!(
            c,
            Call::SetMemoryAccess { access, .. } if *access == MemoryAccess::X
        )),
        1
    );

    Ok(())
}

#[test]
fn breakpoint_controller_insert_propagates_driver_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    // Fail the shadow-frame allocation the interceptor performs first.
    driver.arm_fault(Op::AllocateGfn, 1);
    let vmi = make_vmi(driver)?;
    let mut controller = BreakpointController::<MockDriver>::new();

    assert!(
        controller
            .insert_breakpoint(&vmi, pa_at(CODE_GFN, OFFSET), VIEW)
            .is_err()
    );

    Ok(())
}

#[test]
fn breakpoint_controller_is_breakpoint_detects_int3() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0x90);
    driver.write_original(CODE_GFN, OFFSET as usize, &[0xcc]);
    let vmi = make_vmi(driver)?;

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert!(BreakpointController::<MockDriver>::is_breakpoint(
        &vmi, &event
    )?);

    Ok(())
}

#[test]
fn breakpoint_controller_is_breakpoint_false_without_int3() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0x90);
    let vmi = make_vmi(driver)?;

    let event = bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1);
    assert!(!BreakpointController::<MockDriver>::is_breakpoint(
        &vmi, &event
    )?);

    Ok(())
}

#[test]
fn breakpoint_controller_is_breakpoint_false_for_non_breakpoint_event() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xcc);
    let vmi = make_vmi(driver)?;

    let event = singlestep_event(Some(VIEW), CODE_GFN, va_at(OFFSET));
    assert!(!BreakpointController::<MockDriver>::is_breakpoint(
        &vmi, &event
    )?);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// MemoryController
///////////////////////////////////////////////////////////////////////////////

#[test]
fn memory_controller_check_event_maps_execute_access() -> Result<(), VmiError> {
    let controller = MemoryController::<MockDriver>::new();

    let event = mem_event(Some(VIEW), CODE_GFN, va_at(OFFSET), MemoryAccess::X);
    assert_eq!(controller.check_event(&event), Some((VIEW, CODE_GFN)));

    Ok(())
}

#[test]
fn memory_controller_check_event_ignores_non_execute_and_non_memory() {
    let controller = MemoryController::<MockDriver>::new();

    // Read/write access does not indicate execution from a protected page.
    assert_eq!(
        controller.check_event(&mem_event(
            Some(VIEW),
            CODE_GFN,
            va_at(OFFSET),
            MemoryAccess::RW
        )),
        None
    );
    // A software breakpoint is not a memory-access event.
    assert_eq!(
        controller.check_event(&bp_event(Some(VIEW), CODE_GFN, va_at(OFFSET), ROOT1)),
        None
    );
    // A viewless event cannot resolve.
    assert_eq!(
        controller.check_event(&mem_event(None, CODE_GFN, va_at(OFFSET), MemoryAccess::X)),
        None
    );
}

#[test]
fn memory_controller_monitor_sets_read_write() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut controller = MemoryController::<MockDriver>::new();

    controller.monitor(&vmi, CODE_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(CODE_GFN, VIEW), MemoryAccess::RW);

    Ok(())
}

#[test]
fn memory_controller_unmonitor_restores_rwx() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut controller = MemoryController::<MockDriver>::new();

    controller.monitor(&vmi, CODE_GFN, VIEW)?;
    controller.unmonitor(&vmi, CODE_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(CODE_GFN, VIEW), MemoryAccess::RWX);

    Ok(())
}

#[test]
fn memory_controller_breakpoint_operations_are_noops() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;
    let mut controller = MemoryController::<MockDriver>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    controller.remove_breakpoint(&vmi, pa, VIEW)?;
    // Neither touches the driver.
    assert!(vmi.driver().calls().is_empty());

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Breakpoint builder
///////////////////////////////////////////////////////////////////////////////

#[test]
fn breakpoint_builder_carries_all_fields() {
    let ctx = ctx_at(OFFSET, ROOT1);
    let breakpoint =
        Breakpoint::<u32, &'static str>::from(Breakpoint::new(ctx, VIEW).with_key(7).with_tag("t"));

    assert_eq!(breakpoint.ctx(), ctx);
    assert_eq!(breakpoint.view(), VIEW);
    assert!(!breakpoint.global());
    assert_eq!(breakpoint.key(), 7);
    assert_eq!(breakpoint.tag(), "t");
}

#[test]
fn breakpoint_builder_sets_global_flag() {
    let breakpoint =
        Breakpoint::<(), &'static str>::from(Breakpoint::new(ctx_at(OFFSET, ROOT1), VIEW).global());

    assert!(breakpoint.global());
}

///////////////////////////////////////////////////////////////////////////////
// Regression: shared physical breakpoint (commit 5693644)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn breakpoint_controller_release_shared_reference_does_not_panic() -> Result<(), VmiError> {
    // A physical breakpoint shared by multiple address contexts is reference
    // counted inside the interceptor. Releasing one of several references must
    // not trip the controller's debug assertion.
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut controller = BreakpointController::<MockDriver>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    controller.remove_breakpoint(&vmi, pa, VIEW)?;
    controller.remove_breakpoint(&vmi, pa, VIEW)?;

    Ok(())
}

#[test]
fn manager_page_out_of_shared_return_site_does_not_panic() -> Result<(), VmiError> {
    // Two address contexts share one physical breakpoint; paging out the page
    // releases the references one at a time through the interceptor.
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut manager = BreakpointManager::<BreakpointController<MockDriver>>::new();

    let pa = pa_at(CODE_GFN, OFFSET);
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT1, VIEW), Some(pa))?;
    manager.insert_with_hint(&vmi, bp(OFFSET, ROOT2, VIEW), Some(pa))?;

    let update = PageEntryUpdate {
        view: VIEW,
        ctx: ctx_at(OFFSET, ROOT1),
        pa,
    };
    manager.handle_ptm_event(&vmi, &PageTableMonitorEvent::PageOut(update))?;

    Ok(())
}
