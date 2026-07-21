use vmi_arch_amd64::Amd64;
use vmi_core::{AddressContext, Architecture, Pa, Va, View, VmiError, VmiEvent};

use super::{
    super::BreakpointManager,
    mock::{
        ControllerCall, ControllerFault, DATA_GFN, MockController, OTHER_DATA_GFN, OTHER_ROOT,
        OTHER_VA, OTHER_VIEW, PML4_GFN, ROOT, TEST_VA, VIEW, breakpoint, global_breakpoint,
        other_context, other_pa, software_event, test_context, test_pa, test_vmi, unrelated_event,
    },
};
use crate::ptm::{PageEntryUpdate, PageTableMonitorEvent};

/// Breakpoint manager specialization used by behavioral tests.
type Manager = BreakpointManager<MockController, u8, &'static str>;

/// Creates an empty test manager.
fn new_manager() -> Manager {
    BreakpointManager::new()
}

/// Creates a page-in event.
fn page_in(ctx: AddressContext, pa: Pa, view: View) -> PageTableMonitorEvent {
    PageTableMonitorEvent::PageIn(PageEntryUpdate { view, ctx, pa })
}

/// Creates a page-out event.
fn page_out(ctx: AddressContext, pa: Pa, view: View) -> PageTableMonitorEvent {
    PageTableMonitorEvent::PageOut(PageEntryUpdate { view, ctx, pa })
}

/// Returns sorted tags matched by an event and key.
fn matched_tags(manager: &mut Manager, event: &VmiEvent<Amd64>, key: u8) -> Vec<&'static str> {
    let mut tags = manager
        .get_by_event(event, key)
        .map(|breakpoints| {
            breakpoints
                .map(|breakpoint| breakpoint.tag())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    tags.sort_unstable();
    tags
}

/// Verifies first insertion, exact controller ordering, queries, and duplicate handling.
#[test]
fn active_insertion_installs_monitors_and_supports_queries() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "first");
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);

    assert!(manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Insert(test_pa(), VIEW),
            ControllerCall::Monitor(DATA_GFN, VIEW),
        ]
    );
    assert!(manager.contains_by_address(test_context(), 1));
    assert!(manager.contains_by_event(&event, 1));
    assert_eq!(matched_tags(&mut manager, &event, 1), vec!["first"]);

    vmi.driver().clear_controller_calls();
    assert!(!manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?);
    assert!(vmi.driver().controller_calls().is_empty());

    Ok(())
}

/// Verifies that tags share one physical installation and are removed individually.
#[test]
fn tags_share_a_physical_breakpoint_and_remove_individually() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let first = breakpoint(test_context(), VIEW, 1, "first");
    let second = breakpoint(test_context(), VIEW, 1, "second");
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);

    assert!(manager.insert_with_hint(&vmi, first, Some(test_pa()))?);
    vmi.driver().clear_controller_calls();
    assert!(!manager.insert_with_hint(&vmi, second, Some(test_pa()))?);
    assert!(vmi.driver().controller_calls().is_empty());
    assert_eq!(
        matched_tags(&mut manager, &event, 1),
        vec!["first", "second"]
    );

    assert!(manager.remove_with_hint(&vmi, first, Some(test_pa()))?);
    assert!(vmi.driver().controller_calls().is_empty());
    assert_eq!(matched_tags(&mut manager, &event, 1), vec!["second"]);

    assert!(manager.remove_with_hint(&vmi, second, Some(test_pa()))?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
        ]
    );
    assert!(!manager.contains_by_event(&event, 1));

    Ok(())
}

/// Verifies physical reference counting across keys on one page.
#[test]
fn keys_share_page_monitoring_but_install_separate_references() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let first = breakpoint(test_context(), VIEW, 1, "first");
    let second = breakpoint(test_context(), VIEW, 2, "second");

    assert!(manager.insert_with_hint(&vmi, first, Some(test_pa()))?);
    vmi.driver().clear_controller_calls();
    assert!(manager.insert_with_hint(&vmi, second, Some(test_pa()))?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![ControllerCall::Insert(test_pa(), VIEW)]
    );

    vmi.driver().clear_controller_calls();
    assert!(manager.remove_with_hint(&vmi, first, Some(test_pa()))?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![ControllerCall::Remove(test_pa(), VIEW)]
    );
    assert!(manager.contains_by_address(test_context(), 2));

    vmi.driver().clear_controller_calls();
    assert!(manager.remove_with_hint(&vmi, second, Some(test_pa()))?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
        ]
    );

    Ok(())
}

/// Verifies exact removal of one pending tag followed by page-in activation.
#[test]
fn pending_tags_remove_individually() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let first = breakpoint(test_context(), VIEW, 1, "first");
    let second = breakpoint(test_context(), VIEW, 1, "second");

    assert!(manager.insert_with_hint(&vmi, first, None)?);
    assert!(!manager.insert_with_hint(&vmi, first, None)?);
    assert!(manager.insert_with_hint(&vmi, second, None)?);
    assert!(manager.remove_with_hint(&vmi, first, None)?);

    assert!(manager.handle_ptm_event(&vmi, &page_in(test_context(), test_pa(), VIEW))?);
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    assert_eq!(matched_tags(&mut manager, &event, 1), vec!["second"]);

    Ok(())
}

/// Verifies that removing a pending-only view reports an update.
#[test]
fn remove_by_view_reports_pending_removal() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "pending");

    assert!(manager.insert_with_hint(&vmi, breakpoint, None)?);
    assert!(manager.remove_by_view(&vmi, VIEW)?);
    assert!(!manager.remove_by_view(&vmi, VIEW)?);
    assert!(!manager.remove_with_hint(&vmi, breakpoint, None)?);

    Ok(())
}

/// Verifies that clearing a pending-only manager removes every pending index.
#[test]
fn clear_removes_pending_breakpoints_and_indexes() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "pending");

    manager.insert_with_hint(&vmi, breakpoint, None)?;
    manager.clear(&vmi)?;

    assert!(!manager.remove_with_hint(&vmi, breakpoint, None)?);
    assert!(!manager.remove_by_view(&vmi, VIEW)?);

    Ok(())
}

/// Verifies automatic translation for mapped and unmapped insertion.
#[test]
fn insert_translates_to_active_or_pending_state() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let active = breakpoint(test_context(), VIEW, 1, "active");

    assert!(manager.insert(&vmi, active)?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Insert(test_pa(), VIEW),
            ControllerCall::Monitor(DATA_GFN, VIEW),
        ]
    );

    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let pending = breakpoint(test_context(), VIEW, 1, "pending");
    assert!(manager.insert(&vmi, pending)?);
    assert!(vmi.driver().controller_calls().is_empty());
    assert!(manager.remove(&vmi, pending)?);

    Ok(())
}

/// Verifies propagation of translation errors other than an absent mapping.
#[test]
fn insert_propagates_driver_read_errors_without_state() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    vmi.driver().fail_read(PML4_GFN);

    assert!(matches!(
        manager.insert(&vmi, breakpoint),
        Err(VmiError::Other("injected read failure"))
    ));
    assert!(vmi.driver().controller_calls().is_empty());
    assert!(!manager.contains_by_address(test_context(), 1));

    Ok(())
}

/// Verifies pending-to-active-to-pending transitions across PTM events.
#[test]
fn page_in_and_page_out_move_breakpoints_between_states() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    manager.insert_with_hint(&vmi, breakpoint, None)?;

    assert!(manager.handle_ptm_event(&vmi, &page_in(test_context(), test_pa(), VIEW))?);
    assert!(manager.contains_by_event(&event, 1));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Insert(test_pa(), VIEW),
            ControllerCall::Monitor(DATA_GFN, VIEW),
        ]
    );

    vmi.driver().clear_controller_calls();
    assert!(manager.handle_ptm_event(&vmi, &page_out(test_context(), test_pa(), VIEW))?);
    assert!(!manager.contains_by_event(&event, 1));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
        ]
    );
    assert!(manager.remove_with_hint(&vmi, breakpoint, None)?);

    Ok(())
}

/// Verifies that unrelated PTM events report no update.
#[test]
fn unrelated_ptm_events_are_noops() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();

    assert!(!manager.handle_ptm_event(&vmi, &page_in(other_context(), other_pa(), VIEW))?);
    assert!(!manager.handle_ptm_event(&vmi, &page_out(test_context(), test_pa(), VIEW))?);
    assert!(vmi.driver().controller_calls().is_empty());

    Ok(())
}

/// Verifies batch update aggregation across no-op and matching events.
#[test]
fn ptm_event_batches_report_if_any_event_updates_state() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    manager.insert_with_hint(&vmi, breakpoint(test_context(), VIEW, 1, "target"), None)?;

    assert!(manager.handle_ptm_events(
        &vmi,
        [
            page_in(other_context(), other_pa(), VIEW),
            page_in(test_context(), test_pa(), VIEW),
        ],
    )?);
    assert!(!manager.handle_ptm_events(&vmi, Vec::new())?);

    Ok(())
}

/// Verifies target-view removal while another view remains active.
#[test]
fn remove_by_view_clears_only_the_target_view() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let primary = breakpoint(test_context(), VIEW, 1, "primary");
    let secondary = breakpoint(test_context(), OTHER_VIEW, 1, "secondary");
    let pending = breakpoint(other_context(), VIEW, 2, "pending");

    manager.insert_with_hint(&vmi, primary, Some(test_pa()))?;
    manager.insert_with_hint(&vmi, secondary, Some(test_pa()))?;
    manager.insert_with_hint(&vmi, pending, None)?;
    vmi.driver().clear_controller_calls();

    assert!(manager.remove_by_view(&vmi, VIEW)?);
    assert!(!manager.contains_by_event(&software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT), 1,));
    assert!(manager.contains_by_event(
        &software_event(DATA_GFN, Some(OTHER_VIEW), TEST_VA, ROOT),
        1,
    ));
    assert!(!manager.remove_with_hint(&vmi, pending, None)?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
        ]
    );

    Ok(())
}

/// Verifies that event-driven removal removes the same key and context in every view.
#[test]
fn remove_by_event_removes_matching_locations_across_views() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    manager.insert_with_hint(
        &vmi,
        breakpoint(test_context(), VIEW, 1, "primary"),
        Some(test_pa()),
    )?;
    manager.insert_with_hint(
        &vmi,
        breakpoint(test_context(), OTHER_VIEW, 1, "secondary"),
        Some(test_pa()),
    )?;
    vmi.driver().clear_controller_calls();

    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    assert_eq!(manager.remove_by_event(&vmi, &event, 1)?, Some(true));
    assert!(!manager.contains_by_address(test_context(), 1));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
            ControllerCall::Remove(test_pa(), OTHER_VIEW),
            ControllerCall::Unmonitor(DATA_GFN, OTHER_VIEW),
        ]
    );

    Ok(())
}

/// Verifies event query and removal rejection for unmatched reasons and keys.
#[test]
fn event_operations_reject_unmatched_events_and_keys() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    manager.insert_with_hint(
        &vmi,
        breakpoint(test_context(), VIEW, 1, "target"),
        Some(test_pa()),
    )?;
    vmi.driver().clear_controller_calls();

    let unrelated = unrelated_event(Some(VIEW));
    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    assert!(!manager.contains_by_event(&unrelated, 1));
    assert!(manager.get_by_event(&unrelated, 1).is_none());
    assert_eq!(manager.remove_by_event(&vmi, &unrelated, 1)?, None);
    assert!(!manager.contains_by_event(&event, 2));
    assert!(manager.get_by_event(&event, 2).is_none());
    assert_eq!(manager.remove_by_event(&vmi, &event, 2)?, None);
    assert!(vmi.driver().controller_calls().is_empty());

    Ok(())
}

/// Verifies that event removal reports a page still used by another address.
#[test]
fn remove_by_event_reports_remaining_breakpoints_on_the_page() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let other_va = Va(0x1456);
    let other_ctx = AddressContext::new(other_va, ROOT);
    let other_pa = Amd64::pa_from_gfn(DATA_GFN) + Amd64::va_offset(other_va);
    manager.insert_with_hint(
        &vmi,
        breakpoint(test_context(), VIEW, 1, "first"),
        Some(test_pa()),
    )?;
    manager.insert_with_hint(
        &vmi,
        breakpoint(other_ctx, VIEW, 2, "second"),
        Some(other_pa),
    )?;
    vmi.driver().clear_controller_calls();

    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT);
    assert_eq!(manager.remove_by_event(&vmi, &event, 1)?, Some(false));
    assert!(manager.contains_by_address(other_ctx, 2));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![ControllerCall::Remove(test_pa(), VIEW)]
    );

    Ok(())
}

/// Verifies global matching against the registration root rather than event CR3.
#[test]
fn global_breakpoint_matches_events_from_other_roots() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = global_breakpoint(test_context(), VIEW, 1, "global");
    manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?;

    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, OTHER_ROOT);
    assert!(manager.contains_by_event(&event, 1));
    assert_eq!(matched_tags(&mut manager, &event, 1), vec!["global"]);
    assert!(manager.contains_by_address(test_context(), 1));
    assert!(!manager.contains_by_address(AddressContext::new(TEST_VA, OTHER_ROOT), 1,));

    Ok(())
}

/// Verifies global-root tracking while multiple keys share one physical page.
#[test]
fn global_root_remains_registered_until_all_keys_are_removed() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let first = global_breakpoint(test_context(), VIEW, 1, "first");
    let second = global_breakpoint(AddressContext::new(TEST_VA, OTHER_ROOT), VIEW, 2, "second");

    manager.insert_with_hint(&vmi, first, Some(test_pa()))?;
    manager.insert_with_hint(&vmi, second, Some(test_pa()))?;
    manager.remove_with_hint(&vmi, first, Some(test_pa()))?;

    let event = software_event(DATA_GFN, Some(VIEW), TEST_VA, OTHER_ROOT);
    assert!(manager.contains_by_event(&event, 2));
    assert_eq!(matched_tags(&mut manager, &event, 2), vec!["second"]);

    Ok(())
}

/// Verifies rollback and retry after controller insertion failure.
#[test]
fn insertion_failure_leaves_no_active_state() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    vmi.driver().fail_controller(ControllerFault::Insert);

    assert!(matches!(
        manager.insert_with_hint(&vmi, breakpoint, Some(test_pa())),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert!(!manager.contains_by_address(test_context(), 1));

    assert!(manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?);
    assert!(manager.contains_by_address(test_context(), 1));

    Ok(())
}

/// Verifies rollback of physical installation when page monitoring fails.
#[test]
fn monitor_failure_rolls_back_installation_and_state() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    vmi.driver().fail_controller(ControllerFault::Monitor);

    assert!(matches!(
        manager.insert_with_hint(&vmi, breakpoint, Some(test_pa())),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Insert(test_pa(), VIEW),
            ControllerCall::Monitor(DATA_GFN, VIEW),
            ControllerCall::Remove(test_pa(), VIEW),
        ]
    );
    assert!(!manager.contains_by_address(test_context(), 1));

    assert!(manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?);

    Ok(())
}

/// Verifies state preservation and retry after controller removal failure.
#[test]
fn removal_failure_keeps_breakpoint_active() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?;
    vmi.driver().clear_controller_calls();
    vmi.driver().fail_controller(ControllerFault::Remove);

    assert!(matches!(
        manager.remove_with_hint(&vmi, breakpoint, Some(test_pa())),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert!(manager.contains_by_address(test_context(), 1));

    assert!(manager.remove_with_hint(&vmi, breakpoint, Some(test_pa()))?);
    assert!(!manager.contains_by_address(test_context(), 1));

    Ok(())
}

/// Verifies state and physical rollback when final page unmonitoring fails.
#[test]
fn unmonitor_failure_restores_breakpoint_for_retry() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?;
    vmi.driver().clear_controller_calls();
    vmi.driver().fail_controller(ControllerFault::Unmonitor);

    assert!(matches!(
        manager.remove_with_hint(&vmi, breakpoint, Some(test_pa())),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
            ControllerCall::Insert(test_pa(), VIEW),
        ]
    );
    assert!(manager.contains_by_address(test_context(), 1));

    assert!(manager.remove_with_hint(&vmi, breakpoint, Some(test_pa()))?);

    Ok(())
}

/// Verifies that failed page-in activation preserves pending breakpoints.
#[test]
fn page_in_failure_preserves_pending_state() -> Result<(), VmiError> {
    let vmi = test_vmi(false)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    manager.insert_with_hint(&vmi, breakpoint, None)?;
    vmi.driver().fail_controller(ControllerFault::Insert);
    let event = page_in(test_context(), test_pa(), VIEW);

    assert!(matches!(
        manager.handle_ptm_event(&vmi, &event),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert!(manager.handle_ptm_event(&vmi, &event)?);
    assert!(manager.contains_by_address(test_context(), 1));

    Ok(())
}

/// Verifies that failed page-out removal preserves active breakpoints.
#[test]
fn page_out_failure_preserves_active_state() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let breakpoint = breakpoint(test_context(), VIEW, 1, "target");
    manager.insert_with_hint(&vmi, breakpoint, Some(test_pa()))?;
    vmi.driver().fail_controller(ControllerFault::Remove);
    let event = page_out(test_context(), test_pa(), VIEW);

    assert!(matches!(
        manager.handle_ptm_event(&vmi, &event),
        Err(VmiError::Other("injected controller failure"))
    ));
    assert!(manager.contains_by_address(test_context(), 1));
    assert!(manager.handle_ptm_event(&vmi, &event)?);
    assert!(manager.remove_with_hint(&vmi, breakpoint, None)?);

    Ok(())
}

/// Verifies that clear removes active and pending breakpoints together.
#[test]
fn clear_removes_all_active_and_pending_breakpoints() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    let active = breakpoint(test_context(), VIEW, 1, "active");
    let pending = breakpoint(other_context(), OTHER_VIEW, 2, "pending");
    manager.insert_with_hint(&vmi, active, Some(test_pa()))?;
    manager.insert_with_hint(&vmi, pending, None)?;
    vmi.driver().clear_controller_calls();

    manager.clear(&vmi)?;

    assert!(!manager.contains_by_address(test_context(), 1));
    assert!(!manager.remove_with_hint(&vmi, pending, None)?);
    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Remove(test_pa(), VIEW),
            ControllerCall::Unmonitor(DATA_GFN, VIEW),
        ]
    );

    Ok(())
}

/// Verifies independent pages, offsets, and views use their translated GFNs.
#[test]
fn distinct_locations_are_monitored_independently() -> Result<(), VmiError> {
    let vmi = test_vmi(true)?;
    let mut manager = new_manager();
    manager.insert_with_hint(
        &vmi,
        breakpoint(test_context(), VIEW, 1, "first"),
        Some(test_pa()),
    )?;
    manager.insert_with_hint(
        &vmi,
        breakpoint(other_context(), OTHER_VIEW, 2, "second"),
        Some(other_pa()),
    )?;

    assert_eq!(
        vmi.driver().controller_calls(),
        vec![
            ControllerCall::Insert(test_pa(), VIEW),
            ControllerCall::Monitor(DATA_GFN, VIEW),
            ControllerCall::Insert(other_pa(), OTHER_VIEW),
            ControllerCall::Monitor(OTHER_DATA_GFN, OTHER_VIEW),
        ]
    );
    assert!(manager.contains_by_event(&software_event(DATA_GFN, Some(VIEW), TEST_VA, ROOT), 1,));
    assert!(manager.contains_by_event(
        &software_event(OTHER_DATA_GFN, Some(OTHER_VIEW), OTHER_VA, ROOT),
        2,
    ));

    Ok(())
}
