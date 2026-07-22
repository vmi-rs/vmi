use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use vmi_arch_amd64::{
    Amd64, EventInterrupt, EventReason, EventSinglestep, ExceptionVector, Interrupt, InterruptType,
    Registers,
};
use vmi_core::{
    Architecture as _, Gfn, MemoryAccess, Pa, VcpuId, View, VmiCore, VmiDriver, VmiError, VmiEvent,
    VmiEventFlags, VmiInfo, VmiMappedPage, VmiRead, VmiViewControl, VmiVmControl, VmiWrite,
};

use super::Interceptor;

///////////////////////////////////////////////////////////////////////////////
// Mock Driver
///////////////////////////////////////////////////////////////////////////////

/// A single driver operation recorded by the mock, used to assert the exact
/// sequence of hypervisor interactions the interceptor performs.
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
}

/// In-memory stand-in for a VMI driver.
///
/// Models guest physical pages, per-view GFN remappings, and GFN allocation,
/// records every operation for assertions, and can inject faults into any
/// single driver call.
struct MockDriver {
    /// Guest physical pages, each 4 KiB, indexed by frame number.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,

    /// Active per-view remappings, mapping `(view, original)` to its shadow.
    views: RefCell<HashMap<(View, Gfn), Gfn>>,

    /// Ordered log of every recorded operation.
    log: RefCell<Vec<Call>>,

    /// Next frame number handed out by `allocate_gfn`.
    next_gfn: Cell<u64>,

    /// Next identifier handed out by `create_view`.
    next_view: Cell<u16>,

    /// Per-operation invocation counters.
    counters: RefCell<HashMap<Op, usize>>,

    /// Armed faults, mapping an operation to the 1-based invocation to fail.
    faults: RefCell<HashMap<Op, usize>>,
}

/// Base frame number for shadow pages allocated by the mock. Chosen well above
/// the low frames the tests use for guest pages so the two never collide.
const SHADOW_BASE: u64 = 0x1000;

impl MockDriver {
    /// Creates an empty driver with no pages and no armed faults.
    fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            views: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            next_gfn: Cell::new(SHADOW_BASE),
            next_view: Cell::new(1),
            counters: RefCell::new(HashMap::new()),
            faults: RefCell::new(HashMap::new()),
        }
    }

    /// Inserts a 4 KiB page at `gfn` filled with `byte`.
    fn fill_page(&self, gfn: Gfn, byte: u8) {
        self.pages.borrow_mut().insert(gfn, vec![byte; 4096]);
    }

    /// Overwrites bytes at `offset` within the page at `gfn`, creating a blank
    /// page first if none exists.
    fn write_original(&self, gfn: Gfn, offset: usize, bytes: &[u8]) {
        let mut pages = self.pages.borrow_mut();
        let page = pages.entry(gfn).or_insert_with(|| vec![0u8; 4096]);
        page[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Returns a copy of the whole page at `gfn`.
    fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.pages.borrow().get(&gfn).cloned().expect("page exists")
    }

    /// Returns the byte at `offset` within the page at `gfn`.
    fn byte(&self, gfn: Gfn, offset: usize) -> u8 {
        self.pages.borrow().get(&gfn).expect("page exists")[offset]
    }

    /// Returns the shadow frame currently mapped for `(view, gfn)`, if any.
    fn view_target(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.views.borrow().get(&(view, gfn)).copied()
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
            return Err(VmiError::Other("injected fault"));
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
        let id = self.next_view.get();
        self.next_view.set(id + 1);
        Ok(View(id))
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

///////////////////////////////////////////////////////////////////////////////
// Test Helpers
///////////////////////////////////////////////////////////////////////////////

/// Primary view used by most tests.
const VIEW: View = View(0);

/// Secondary view used by multi-view tests.
const VIEW2: View = View(3);

/// Guest code page a breakpoint is installed into.
const CODE_GFN: Gfn = Gfn(0x10);

/// A second, unrelated guest code page.
const OTHER_GFN: Gfn = Gfn(0x11);

/// Page-aligned in-page offset used for the primary breakpoint.
const OFFSET: u64 = 0x100;

/// Page-aligned virtual base for synthesizing events. Only the low 12 bits
/// (the page offset) are consulted by `contains_breakpoint`.
const EVENT_IP_BASE: u64 = 0xffff_f800_0004_0000;

/// Returns the physical address of `offset` within the page at `gfn`.
fn bp_address(gfn: Gfn, offset: u64) -> Pa {
    Amd64::pa_from_gfn(gfn) + offset
}

/// Wraps a driver in a `VmiCore` with the page cache disabled, matching how the
/// interceptor is exercised in production where shadow updates bypass the cache.
fn make_vmi(driver: MockDriver) -> Result<VmiCore<MockDriver>, VmiError> {
    let mut vmi = VmiCore::new(driver)?;
    vmi.disable_gfn_cache();
    Ok(vmi)
}

/// Builds a software-breakpoint event at `(view, gfn, offset)`.
fn breakpoint_event(view: Option<View>, gfn: Gfn, offset: u64) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: EVENT_IP_BASE | offset,
        ..Default::default()
    };
    let reason = EventReason::Interrupt(EventInterrupt {
        gfn,
        interrupt: Interrupt::breakpoint(1),
    });
    VmiEvent::new(VcpuId(0), VmiEventFlags::empty(), view, registers, reason)
}

/// Builds a singlestep event, which is never a software breakpoint.
fn singlestep_event(view: Option<View>, gfn: Gfn, offset: u64) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: EVENT_IP_BASE | offset,
        ..Default::default()
    };
    let reason = EventReason::Singlestep(EventSinglestep { gfn });
    VmiEvent::new(VcpuId(0), VmiEventFlags::empty(), view, registers, reason)
}

/// Builds an interrupt event whose vector is `#BP` but whose type is a hardware
/// exception, which is not a software breakpoint.
fn hardware_breakpoint_event(view: Option<View>, gfn: Gfn, offset: u64) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: EVENT_IP_BASE | offset,
        ..Default::default()
    };
    let reason = EventReason::Interrupt(EventInterrupt {
        gfn,
        interrupt: Interrupt {
            vector: ExceptionVector::Breakpoint,
            typ: InterruptType::HardwareException,
            error_code: 0,
            instruction_length: 1,
            extra: 0,
        },
    });
    VmiEvent::new(VcpuId(0), VmiEventFlags::empty(), view, registers, reason)
}

/// Convenience predicate: any `AllocateGfn` call.
fn is_allocate(call: &Call) -> bool {
    matches!(call, Call::AllocateGfn(_))
}

/// Convenience predicate: any `ChangeViewGfn` call.
fn is_change_view(call: &Call) -> bool {
    matches!(call, Call::ChangeViewGfn { .. })
}

/// Convenience predicate: any `ResetViewGfn` call.
fn is_reset_view(call: &Call) -> bool {
    matches!(call, Call::ResetViewGfn { .. })
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Shadow Creation
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_allocates_shadow_and_remaps_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // A distinct shadow frame is allocated and the view is remapped to it.
    assert_ne!(shadow, CODE_GFN);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
    assert_eq!(vmi.driver().count(is_allocate), 1);

    Ok(())
}

#[test]
fn insert_returns_shadow_gfn_matching_view_target() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // The returned GFN is exactly the frame the view was remapped to.
    assert_eq!(Some(shadow), vmi.driver().view_target(VIEW, CODE_GFN));

    Ok(())
}

#[test]
fn insert_copies_original_into_shadow_and_writes_breakpoint() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    let shadow_page = vmi.driver().page(shadow);
    // Every byte matches the original except the breakpoint byte.
    for (i, &b) in shadow_page.iter().enumerate() {
        if i as u64 == OFFSET {
            assert_eq!(b, 0xcc, "breakpoint byte at offset");
        }
        else {
            assert_eq!(b, 0xab, "original byte preserved at {i}");
        }
    }

    Ok(())
}

#[test]
fn insert_leaves_original_page_untouched() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // The original guest page is never modified; only the shadow carries 0xcc.
    assert!(vmi.driver().page(CODE_GFN).iter().all(|&b| b == 0xab));

    Ok(())
}

#[test]
fn insert_performs_expected_driver_sequence() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // The full, ordered set of hypervisor operations for a fresh breakpoint:
    // allocate the shadow, copy the original into it, remap the view, then read
    // the shadow to capture the original byte and overwrite it with 0xcc.
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::AllocateGfn(shadow),
            Call::ReadPage(CODE_GFN),
            Call::WritePage {
                gfn: shadow,
                offset: 0,
                len: 4096,
            },
            Call::ChangeViewGfn {
                view: VIEW,
                old: CODE_GFN,
                new: shadow,
            },
            Call::ReadPage(shadow),
            Call::WritePage {
                gfn: shadow,
                offset: OFFSET,
                len: 1,
            },
        ]
    );

    Ok(())
}

#[test]
fn insert_at_offset_zero() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0), VIEW)?;

    assert_eq!(vmi.driver().byte(shadow, 0), 0xcc);
    assert_eq!(vmi.driver().byte(shadow, 1), 0xab);

    Ok(())
}

#[test]
fn insert_at_last_byte_of_page() -> Result<(), VmiError> {
    // The single-byte AMD64 breakpoint fits exactly at the final page offset;
    // this must not be rejected as out of bounds nor panic while slicing.
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 4095), VIEW)?;

    assert_eq!(vmi.driver().byte(shadow, 4095), 0xcc);
    assert_eq!(vmi.driver().byte(shadow, 4094), 0xab);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Reference Counting and Duplicates
///////////////////////////////////////////////////////////////////////////////

#[test]
fn duplicate_insert_returns_same_shadow_without_touching_driver() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let first = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;
    vmi.driver().clear_log();

    let second = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // A second reference reuses the shadow and performs no driver operations.
    assert_eq!(first, second);
    assert!(vmi.driver().calls().is_empty());

    Ok(())
}

#[test]
fn insert_reference_count_requires_matching_removes() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // Two references: the first remove only releases a reference, the second
    // removes the physical breakpoint.
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(false)
    );
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Multiple Breakpoints per Page
///////////////////////////////////////////////////////////////////////////////

#[test]
fn two_breakpoints_same_page_share_one_shadow() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow_a = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    let shadow_b = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    // Both breakpoints live in the same shadow, allocated and remapped once.
    assert_eq!(shadow_a, shadow_b);
    assert_eq!(vmi.driver().count(is_allocate), 1);
    assert_eq!(vmi.driver().count(is_change_view), 1);

    assert_eq!(vmi.driver().byte(shadow_a, 0x100), 0xcc);
    assert_eq!(vmi.driver().byte(shadow_a, 0x200), 0xcc);

    Ok(())
}

#[test]
fn second_breakpoint_preserves_first_and_captures_correct_original() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    // Give the two breakpoint sites distinct original bytes.
    driver.write_original(CODE_GFN, 0x100, &[0x11]);
    driver.write_original(CODE_GFN, 0x200, &[0x22]);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    // Removing the second breakpoint restores its own original byte and leaves
    // the first breakpoint installed.
    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;
    let shadow = vmi
        .driver()
        .view_target(VIEW, CODE_GFN)
        .expect("still mapped");
    assert_eq!(vmi.driver().byte(shadow, 0x200), 0x22);
    assert_eq!(vmi.driver().byte(shadow, 0x100), 0xcc);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Insert: Multiple Views and Pages
///////////////////////////////////////////////////////////////////////////////

#[test]
fn same_gfn_in_two_views_gets_independent_shadows() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow0 = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    let shadow1 = interceptor.insert_breakpoint(&vmi, address, VIEW2)?;

    // Each view is tracked independently and gets its own shadow frame.
    assert_ne!(shadow0, shadow1);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow0));
    assert_eq!(vmi.driver().view_target(VIEW2, CODE_GFN), Some(shadow1));
    assert_eq!(vmi.driver().count(is_allocate), 2);

    Ok(())
}

#[test]
fn two_pages_get_independent_shadows() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    driver.fill_page(OTHER_GFN, 0xcd);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow_a = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;
    let shadow_b = interceptor.insert_breakpoint(&vmi, bp_address(OTHER_GFN, OFFSET), VIEW)?;

    assert_ne!(shadow_a, shadow_b);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow_a));
    assert_eq!(vmi.driver().view_target(VIEW, OTHER_GFN), Some(shadow_b));

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Remove: Basics
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_only_breakpoint_restores_original_and_resets_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );

    // The shadow byte is restored and the view mapping is torn down.
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xab);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    Ok(())
}

#[test]
fn remove_last_breakpoint_performs_expected_driver_sequence() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().clear_log();

    interceptor.remove_breakpoint(&vmi, address, VIEW)?;

    // Removing the last breakpoint restores the original byte then resets the
    // view mapping.
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::WritePage {
                gfn: shadow,
                offset: OFFSET,
                len: 1,
            },
            Call::ResetViewGfn {
                view: VIEW,
                gfn: CODE_GFN,
            },
        ]
    );

    Ok(())
}

#[test]
fn remove_unknown_page_returns_none() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    // Nothing was ever inserted here.
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?,
        None
    );

    Ok(())
}

#[test]
fn remove_unknown_offset_returns_none() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;

    // The page is tracked but has no breakpoint at this offset.
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?,
        None
    );

    Ok(())
}

#[test]
fn remove_wrong_view_returns_none() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // The breakpoint exists in VIEW, not VIEW2.
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW2)?, None);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Remove: Multiple Breakpoints per Page
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_one_of_two_keeps_view_mapped() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;

    // The page still has a breakpoint, so the view stays mapped and no reset
    // is issued.
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
    assert_eq!(vmi.driver().count(is_reset_view), 0);
    assert_eq!(vmi.driver().byte(shadow, 0x100), 0xab);
    assert_eq!(vmi.driver().byte(shadow, 0x200), 0xcc);

    Ok(())
}

#[test]
fn remove_last_of_several_resets_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    assert_eq!(vmi.driver().count(is_reset_view), 0);

    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;
    // Now the page is empty and the view is reset exactly once.
    assert_eq!(vmi.driver().count(is_reset_view), 1);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Remove: Reference Counting
///////////////////////////////////////////////////////////////////////////////

#[test]
fn remove_referenced_breakpoint_keeps_it_installed() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().clear_log();

    // Releasing one of two references leaves the physical breakpoint in place
    // and performs no driver operations.
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(false)
    );
    assert!(vmi.driver().calls().is_empty());
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));

    Ok(())
}

#[test]
fn three_references_need_three_removes() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(false)
    );
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(false)
    );
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );
    // Past the last reference, nothing remains.
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Remove: Force
///////////////////////////////////////////////////////////////////////////////

#[test]
fn force_remove_ignores_reference_count() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // Force removal drops all references at once.
    assert_eq!(
        interceptor.remove_breakpoint_by_force(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xab);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    // Nothing remains afterwards.
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);

    Ok(())
}

#[test]
fn force_remove_single_reference_behaves_like_remove() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    assert_eq!(
        interceptor.remove_breakpoint_by_force(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xab);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    Ok(())
}

#[test]
fn force_remove_unknown_returns_none() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    assert_eq!(
        interceptor.remove_breakpoint_by_force(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?,
        None
    );

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Reactivation after Full Removal
///////////////////////////////////////////////////////////////////////////////

#[test]
fn reinsert_after_removal_reuses_shadow_and_remaps_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    vmi.driver().clear_log();

    let shadow_again = interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // The retained shadow is reused (no new allocation) and the view is mapped
    // back to it, otherwise the reinserted breakpoint would be inactive.
    assert_eq!(shadow_again, shadow);
    assert_eq!(vmi.driver().count(is_allocate), 0);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);

    Ok(())
}

#[test]
fn reinsert_after_removal_performs_expected_driver_sequence() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().clear_log();

    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // Reinsertion refreshes and remaps the retained shadow, then installs the
    // breakpoint, without allocating a new frame.
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::ReadPage(CODE_GFN),
            Call::WritePage {
                gfn: shadow,
                offset: 0,
                len: 4096,
            },
            Call::ChangeViewGfn {
                view: VIEW,
                old: CODE_GFN,
                new: shadow,
            },
            Call::ReadPage(shadow),
            Call::WritePage {
                gfn: shadow,
                offset: OFFSET,
                len: 1,
            },
        ]
    );

    Ok(())
}

#[test]
fn reinsert_refreshes_shadow_from_modified_original() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;

    // The guest rewrites the original page while no breakpoint is present.
    vmi.driver().fill_page(CODE_GFN, 0x5a);

    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // The shadow reflects the new original everywhere but the breakpoint byte.
    let shadow_page = vmi.driver().page(shadow);
    for (i, &b) in shadow_page.iter().enumerate() {
        if i as u64 == OFFSET {
            assert_eq!(b, 0xcc);
        }
        else {
            assert_eq!(b, 0x5a, "refreshed original byte at {i}");
        }
    }

    // Removing again restores the refreshed original byte, not the stale one.
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0x5a);

    Ok(())
}

#[test]
fn reinsert_at_different_offset_after_removal_reactivates() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    vmi.driver().clear_log();

    // Reinserting at a different offset on the now-empty page still reactivates.
    let shadow_again = interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    assert_eq!(shadow_again, shadow);
    assert_eq!(vmi.driver().count(is_allocate), 0);
    assert_eq!(vmi.driver().count(is_change_view), 1);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
    assert_eq!(vmi.driver().byte(shadow, 0x200), 0xcc);
    assert_eq!(vmi.driver().byte(shadow, 0x100), 0xab);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// contains_breakpoint
///////////////////////////////////////////////////////////////////////////////

#[test]
fn contains_true_for_installed_breakpoint() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    let event = breakpoint_event(Some(VIEW), CODE_GFN, OFFSET);
    assert!(interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_for_non_breakpoint_reason() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // A singlestep event is not a software breakpoint.
    let event = singlestep_event(Some(VIEW), CODE_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_for_hardware_breakpoint_exception() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    // Same vector but a hardware exception type is not a software breakpoint.
    let event = hardware_breakpoint_event(Some(VIEW), CODE_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_when_view_is_none() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    let event = breakpoint_event(None, CODE_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_for_untracked_gfn() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    let event = breakpoint_event(Some(VIEW), OTHER_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_for_untracked_view() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?;

    let event = breakpoint_event(Some(VIEW2), CODE_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_for_offset_without_breakpoint() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;

    // Correct page and view, but no breakpoint at this offset.
    let event = breakpoint_event(Some(VIEW), CODE_GFN, 0x200);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_false_after_removal() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;

    let event = breakpoint_event(Some(VIEW), CODE_GFN, OFFSET);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_true_after_reference_decrement() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // One reference released, but the physical breakpoint is still installed.
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;

    let event = breakpoint_event(Some(VIEW), CODE_GFN, OFFSET);
    assert!(interceptor.contains_breakpoint(&event));

    Ok(())
}

#[test]
fn contains_true_for_each_of_multiple_breakpoints() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x100), VIEW)?;
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;

    assert!(interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, 0x100)));
    assert!(interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, 0x200)));
    assert!(!interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, 0x300)));

    Ok(())
}

#[test]
fn contains_distinguishes_views() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    // Same address in both views.
    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW2)?;

    // Remove it from VIEW only.
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;

    assert!(!interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, OFFSET)));
    assert!(interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW2), CODE_GFN, OFFSET)));

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Error Propagation
///////////////////////////////////////////////////////////////////////////////

#[test]
fn insert_propagates_allocate_gfn_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    driver.arm_fault(Op::AllocateGfn, 1);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());

    // Nothing was tracked or remapped, and a later remove finds nothing.
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);

    Ok(())
}

#[test]
fn insert_propagates_read_page_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    driver.arm_fault(Op::ReadPage, 1);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    Ok(())
}

#[test]
fn insert_propagates_change_view_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    driver.arm_fault(Op::ChangeView, 1);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());

    // The view was never mapped and the page is not tracked.
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);

    Ok(())
}

#[test]
fn insert_propagates_breakpoint_write_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    // The first write copies the page into the shadow; the second writes the
    // breakpoint byte. Fail the second.
    driver.arm_fault(Op::WritePage, 2);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());

    Ok(())
}

#[test]
fn remove_propagates_restore_write_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    // Fail the next write, which is the restore during removal.
    vmi.driver().arm_fault(Op::WritePage, 3);
    assert!(interceptor.remove_breakpoint(&vmi, address, VIEW).is_err());

    // The failed restore left the breakpoint byte and view mapping intact, so a
    // retry still finds the breakpoint.
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));

    Ok(())
}

#[test]
fn failed_activation_does_not_leak_shadow_gfn() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    // Fail the view remap during the first activation of a new page.
    driver.arm_fault(Op::ChangeView, 1);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    // The first insert allocates a shadow frame, then fails to activate it.
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());

    // Retrying (the second view remap is not armed to fail) must reuse the frame
    // the failed attempt allocated rather than leaking it and allocating another.
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    assert_eq!(vmi.driver().count(is_allocate), 1);
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);

    Ok(())
}
