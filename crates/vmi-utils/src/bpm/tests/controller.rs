use vmi_arch_amd64::Amd64;
use vmi_core::{Architecture, MemoryAccess, VmiError};

use super::{
    super::{BreakpointController, MemoryController, TapController},
    mock::{
        DATA_GFN, MockBpmDriver, ROOT, TEST_VA, VIEW, memory_event, software_event, test_pa,
        test_vmi, unrelated_event,
    },
};

/// Verifies software-breakpoint event classification and view requirements.
#[test]
fn breakpoint_controller_classifies_software_events() -> Result<(), VmiError> {
    let controller = BreakpointController::<MockBpmDriver>::new();
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);

    assert_eq!(controller.check_event(&event), Some((VIEW, DATA_GFN)));
    assert_eq!(
        controller.check_event(&software_event(DATA_GFN, None, TEST_VA, ROOT)),
        None
    );
    assert_eq!(controller.check_event(&unrelated_event(Some(VIEW))), None);

    Ok(())
}

/// Verifies content-based software-breakpoint detection.
#[test]
fn breakpoint_controller_checks_the_faulting_instruction_bytes() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    vmi.driver()
        .set_bytes(DATA_GFN, Amd64::va_offset(TEST_VA), Amd64::BREAKPOINT);

    assert!(BreakpointController::<MockBpmDriver>::is_breakpoint(
        &vmi, &event
    )?);
    assert!(!BreakpointController::<MockBpmDriver>::is_breakpoint(
        &vmi,
        &unrelated_event(Some(VIEW)),
    )?);

    let vmi = test_vmi(true)?;
    assert!(!BreakpointController::<MockBpmDriver>::is_breakpoint(
        &vmi, &event
    )?);

    Ok(())
}

/// Verifies the software controller's insert, monitor, remove, and unmonitor lifecycle.
#[test]
fn breakpoint_controller_manages_shadow_and_page_permissions() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut controller = BreakpointController::<MockBpmDriver>::new();
    let pa = test_pa();

    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    let shadow = vmi
        .driver()
        .mapping(DATA_GFN, VIEW)
        .expect("breakpoint insertion must map a shadow page");
    assert_eq!(
        vmi.driver().page(shadow)[Amd64::pa_offset(pa) as usize],
        Amd64::BREAKPOINT[0]
    );

    controller.monitor(&vmi, DATA_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::X);

    controller.remove_breakpoint(&vmi, pa, VIEW)?;
    assert_eq!(vmi.driver().mapping(DATA_GFN, VIEW), None);

    controller.unmonitor(&vmi, DATA_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::RWX);

    Ok(())
}

/// Verifies execute-access event classification for the memory controller.
#[test]
fn memory_controller_matches_only_execute_access_with_a_view() -> Result<(), VmiError> {
    let controller = MemoryController::<MockBpmDriver>::new();
    let pa = test_pa();

    assert_eq!(
        controller.check_event(&memory_event(pa, Some(VIEW), MemoryAccess::X)),
        Some((VIEW, DATA_GFN))
    );
    assert_eq!(
        controller.check_event(&memory_event(pa, Some(VIEW), MemoryAccess::RX)),
        Some((VIEW, DATA_GFN))
    );
    assert_eq!(
        controller.check_event(&memory_event(pa, Some(VIEW), MemoryAccess::R)),
        None
    );
    assert_eq!(
        controller.check_event(&memory_event(pa, None, MemoryAccess::X)),
        None
    );
    assert_eq!(controller.check_event(&unrelated_event(Some(VIEW))), None);

    Ok(())
}

/// Verifies memory-controller permissions and no-op breakpoint hooks.
#[test]
fn memory_controller_toggles_execute_permission() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut controller = MemoryController::<MockBpmDriver>::new();
    let pa = test_pa();

    controller.insert_breakpoint(&vmi, pa, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::RWX);

    controller.monitor(&vmi, DATA_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::RW);

    controller.remove_breakpoint(&vmi, pa, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::RW);

    controller.unmonitor(&vmi, DATA_GFN, VIEW)?;
    assert_eq!(vmi.driver().access(DATA_GFN, VIEW), MemoryAccess::RWX);

    Ok(())
}
