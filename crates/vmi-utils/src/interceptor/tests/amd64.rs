use vmi_arch_amd64::{
    Amd64, EventInterrupt, EventReason, EventSinglestep, ExceptionVector, Interrupt, InterruptType,
    Registers,
};
use vmi_core::{
    Architecture as _, Gfn, Pa, VcpuId, View, VmiCore, VmiError, VmiEvent, VmiEventFlags, VmiRead,
};
use vmi_driver_mock::arch::amd64::{Call, MockDriver, Op};

use super::super::Interceptor;

///////////////////////////////////////////////////////////////////////////////
// Test Helpers
///////////////////////////////////////////////////////////////////////////////

/// Primary view used by most tests.
const VIEW: View = View(0);

/// Secondary view used by multi-view tests.
const VIEW2: View = View(3);

/// Guest code page that receives the test breakpoints.
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
    matches!(call, Call::AllocateGfn { .. })
}

///////////////////////////////////////////////////////////////////////////////
// Construction
///////////////////////////////////////////////////////////////////////////////

#[test]
fn new_and_default_start_without_breakpoints() -> Result<(), VmiError> {
    let vmi = make_vmi(MockDriver::new())?;

    // Both constructors yield an interceptor that tracks nothing: no event
    // matches and removing any address reports "not found".
    for mut interceptor in [
        Interceptor::<MockDriver>::new(),
        Interceptor::<MockDriver>::default(),
    ] {
        let event = breakpoint_event(Some(VIEW), CODE_GFN, OFFSET);
        assert!(!interceptor.contains_breakpoint(&event));
        assert_eq!(
            interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET), VIEW)?,
            None
        );
    }

    Ok(())
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

    // Both breakpoints share one allocated frame.
    assert_eq!(shadow_a, shadow_b);
    assert_eq!(vmi.driver().count(is_allocate), 1);

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

    // The original mapping is restored and its replacement is reclaimed.
    assert_eq!(vmi.driver().byte(CODE_GFN, OFFSET as usize), 0xab);
    assert!(vmi.driver().read_page(shadow).is_err());
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);

    Ok(())
}

#[test]
fn remove_restores_an_original_int3_opcode() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    // The original instruction at the target is itself an INT3 (0xcc), equal to
    // the breakpoint opcode.
    driver.write_original(CODE_GFN, OFFSET as usize, &[0xcc]);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET + 1), VIEW)?;

    vmi.driver().clear_log();
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );

    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    assert!(interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, OFFSET + 1)));

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

    // Removing one patch preserves the executable mapping and remaining patch.
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), Some(shadow));
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

    interceptor.remove_breakpoint(&vmi, bp_address(CODE_GFN, 0x200), VIEW)?;
    // The empty page returns to the original mapping.
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
    assert!(vmi.driver().read_page(shadow).is_err());
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
    assert!(vmi.driver().read_page(shadow).is_err());
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

/// Reclaims successful removals and uses current original bytes on reinsertion.
#[test]
fn reinsert_after_removal_uses_current_code() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();
    let address = bp_address(CODE_GFN, OFFSET);
    let old_shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.remove_breakpoint(&vmi, address, VIEW)?;
    assert!(vmi.driver().read_page(old_shadow).is_err());
    vmi.driver().fill_page(CODE_GFN, 0x5a);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    assert_eq!(vmi.driver().byte(shadow, OFFSET as usize), 0xcc);
    assert_eq!(vmi.driver().byte(shadow, 0), 0x5a);
    assert_eq!(vmi.driver().byte(CODE_GFN, OFFSET as usize), 0x5a);
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

    // The view was never mapped and no breakpoint owns the retained frame.
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);

    Ok(())
}

#[test]
fn insert_propagates_breakpoint_write_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    driver.arm_fault(Op::WritePage, 1);

    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();

    let address = bp_address(CODE_GFN, OFFSET);
    assert!(interceptor.insert_breakpoint(&vmi, address, VIEW).is_err());

    Ok(())
}

/// Keeps patches tracked when an edit fails.
#[test]
fn remove_propagates_restore_write_error() -> Result<(), VmiError> {
    let driver = MockDriver::new();
    driver.fill_page(CODE_GFN, 0xab);
    let vmi = make_vmi(driver)?;
    let mut interceptor = Interceptor::<MockDriver>::new();
    let address = bp_address(CODE_GFN, OFFSET);
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, bp_address(CODE_GFN, OFFSET + 1), VIEW)?;
    vmi.driver().arm_fault(Op::WritePage, 3);
    assert!(interceptor.remove_breakpoint(&vmi, address, VIEW).is_err());
    assert_eq!(vmi.driver().view_target(VIEW, CODE_GFN), None);
    assert!(interceptor.contains_breakpoint(&breakpoint_event(Some(VIEW), CODE_GFN, OFFSET)));
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

/// Rejects unaligned and crossing multi-byte instructions before guest access.
#[test]
fn validates_multibyte_alignment_and_page_containment() {
    for offset in [1, 2, 3, 4093, 4094, 4095, 4096] {
        assert!(super::super::validate_breakpoint(offset, 4, 4096).is_err());
    }
    assert!(super::super::validate_breakpoint(4092, 4, 4096).is_ok());
    assert!(super::super::validate_breakpoint(4095, 1, 4096).is_ok());
}
