use vmi_arch_amd64::Amd64;
use vmi_core::{Architecture, Gfn, VmiError};

use self::mock::{
    Call, FIRST_SHADOW_GFN, Fault, MockInterceptorDriver, OFFSET, ORIGINAL_GFN, OTHER_GFN,
    OTHER_OFFSET, OTHER_VIEW, VIEW, address, assert_injected_error, breakpoint_event,
    non_breakpoint_event, page_content, test_vmi, with_breakpoint,
};
use super::Interceptor;

/// Verifies breakpoint rejection for multi-byte instructions at page boundaries.
mod cross_page;

/// Provides observable driver state and deterministic interceptor fixtures.
mod mock;

/// Verifies that both constructors produce an empty interceptor.
#[test]
fn new_and_default_start_without_breakpoints() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let event = breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET);

    let mut new = Interceptor::<MockInterceptorDriver>::new();
    let mut default = Interceptor::<MockInterceptorDriver>::default();

    assert!(!new.contains_breakpoint(&event));
    assert!(!default.contains_breakpoint(&event));
    assert_eq!(
        new.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?,
        None
    );
    assert_eq!(
        default.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?,
        None
    );
    assert!(vmi.driver().calls().is_empty());

    Ok(())
}

/// Verifies the complete driver operation sequence for the first insertion.
#[test]
fn first_insert_copies_patches_and_maps_a_shadow_page() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;

    assert_eq!(shadow, FIRST_SHADOW_GFN);
    assert_eq!(vmi.driver().page(ORIGINAL_GFN), original);
    assert_eq!(vmi.driver().page(shadow), with_breakpoint(original, OFFSET));
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::Allocate(shadow),
            Call::Read(ORIGINAL_GFN),
            Call::Write(shadow, 0, Amd64::PAGE_SIZE as usize),
            Call::Change(VIEW, ORIGINAL_GFN, shadow),
            Call::Read(shadow),
            Call::Write(shadow, OFFSET, Amd64::BREAKPOINT.len()),
        ]
    );

    Ok(())
}

/// Verifies that an AMD64 breakpoint can occupy the page's final byte.
#[test]
fn insert_supports_the_last_byte_of_a_page() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let last_offset = Amd64::PAGE_SIZE - Amd64::BREAKPOINT.len() as u64;
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, last_offset), VIEW)?;

    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(original, last_offset)
    );

    Ok(())
}

/// Verifies restoration when the original byte already equals INT3.
#[test]
fn insert_preserves_an_original_breakpoint_opcode_for_removal() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let mut original = vmi.driver().page(ORIGINAL_GFN);
    original[OFFSET as usize] = Amd64::BREAKPOINT[0];
    vmi.driver().replace_page(ORIGINAL_GFN, original.clone());
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;
    assert_eq!(vmi.driver().page(shadow), original);

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);

    Ok(())
}

/// Verifies reference counting without redundant driver operations.
#[test]
fn duplicate_insert_adds_a_reference_without_touching_the_driver() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    let address = address(ORIGINAL_GFN, OFFSET);

    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().clear_calls();
    assert_eq!(interceptor.insert_breakpoint(&vmi, address, VIEW)?, shadow);
    assert!(vmi.driver().calls().is_empty());

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(false)
    );
    assert!(vmi.driver().calls().is_empty());
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(original.clone(), OFFSET)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::Write(shadow, OFFSET, Amd64::BREAKPOINT.len()),
            Call::Reset(VIEW, ORIGINAL_GFN),
        ]
    );

    Ok(())
}

/// Verifies that offsets on one page share and independently restore a shadow.
#[test]
fn multiple_breakpoints_share_a_shadow_and_restore_independently() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let first_address = address(ORIGINAL_GFN, OFFSET);
    let second_address = address(ORIGINAL_GFN, OTHER_OFFSET);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, first_address, VIEW)?;
    assert_eq!(
        interceptor.insert_breakpoint(&vmi, second_address, VIEW)?,
        shadow
    );
    assert_eq!(vmi.driver().allocation_count(), 1);
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(with_breakpoint(original.clone(), OFFSET), OTHER_OFFSET)
    );

    vmi.driver().clear_calls();
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, first_address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().reset_count(), 0);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(original.clone(), OTHER_OFFSET)
    );
    assert!(!interceptor.contains_breakpoint(&breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET)));
    assert!(interceptor.contains_breakpoint(&breakpoint_event(
        ORIGINAL_GFN,
        Some(VIEW),
        OTHER_OFFSET
    )));

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, second_address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);

    Ok(())
}

/// Verifies that forced removal discards every reference.
#[test]
fn force_remove_discards_all_references() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let address = address(ORIGINAL_GFN, OFFSET);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    interceptor.insert_breakpoint(&vmi, address, VIEW)?;

    assert_eq!(
        interceptor.remove_breakpoint_by_force(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert_eq!(interceptor.remove_breakpoint(&vmi, address, VIEW)?, None);
    assert_eq!(
        interceptor.remove_breakpoint_by_force(&vmi, address, VIEW)?,
        None
    );

    Ok(())
}

/// Verifies that unknown pages, offsets, and views cause no side effects.
#[test]
fn removing_unknown_page_or_offset_is_a_noop() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?,
        None
    );
    assert!(vmi.driver().calls().is_empty());

    let shadow = interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;
    vmi.driver().clear_calls();
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OTHER_OFFSET), VIEW)?,
        None
    );
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), OTHER_VIEW)?,
        None
    );
    assert!(vmi.driver().calls().is_empty());
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));

    Ok(())
}

/// Verifies that different original pages receive independent shadows.
#[test]
fn different_original_pages_use_independent_shadows() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let other = vmi.driver().page(OTHER_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let first_shadow = interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;
    let second_shadow =
        interceptor.insert_breakpoint(&vmi, address(OTHER_GFN, OTHER_OFFSET), VIEW)?;

    assert_ne!(first_shadow, second_shadow);
    assert_eq!(
        vmi.driver().page(first_shadow),
        with_breakpoint(original, OFFSET)
    );
    assert_eq!(
        vmi.driver().page(second_shadow),
        with_breakpoint(other, OTHER_OFFSET)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(first_shadow));
    assert_eq!(vmi.driver().mapping(VIEW, OTHER_GFN), Some(second_shadow));

    Ok(())
}

/// Verifies that one original page remains independent across views.
#[test]
fn the_same_original_page_is_independent_between_views() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    let address = address(ORIGINAL_GFN, OFFSET);

    let first_shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    let second_shadow = interceptor.insert_breakpoint(&vmi, address, OTHER_VIEW)?;

    assert_ne!(first_shadow, second_shadow);
    assert_eq!(
        vmi.driver().page(first_shadow),
        with_breakpoint(original.clone(), OFFSET)
    );
    assert_eq!(
        vmi.driver().page(second_shadow),
        with_breakpoint(original, OFFSET)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(first_shadow));
    assert_eq!(
        vmi.driver().mapping(OTHER_VIEW, ORIGINAL_GFN),
        Some(second_shadow)
    );

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert_eq!(
        vmi.driver().mapping(OTHER_VIEW, ORIGINAL_GFN),
        Some(second_shadow)
    );
    assert!(!interceptor.contains_breakpoint(&breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET)));
    assert!(interceptor.contains_breakpoint(&breakpoint_event(
        ORIGINAL_GFN,
        Some(OTHER_VIEW),
        OFFSET
    )));

    Ok(())
}

/// Verifies that reinsertion refreshes and reuses an inactive shadow.
#[test]
fn reinsert_reuses_and_refreshes_an_inactive_shadow() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let first_address = address(ORIGINAL_GFN, OFFSET);
    let second_address = address(ORIGINAL_GFN, OTHER_OFFSET);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();

    let shadow = interceptor.insert_breakpoint(&vmi, first_address, VIEW)?;
    assert_eq!(
        interceptor.remove_breakpoint(&vmi, first_address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);

    let replacement = page_content(0x40);
    vmi.driver().replace_page(ORIGINAL_GFN, replacement.clone());
    vmi.driver().clear_calls();

    assert_eq!(
        interceptor.insert_breakpoint(&vmi, second_address, VIEW)?,
        shadow
    );
    assert_eq!(vmi.driver().allocation_count(), 0);
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(replacement, OTHER_OFFSET)
    );
    assert_eq!(
        vmi.driver().calls(),
        vec![
            Call::Read(ORIGINAL_GFN),
            Call::Write(shadow, 0, Amd64::PAGE_SIZE as usize),
            Call::Change(VIEW, ORIGINAL_GFN, shadow),
            Call::Read(shadow),
            Call::Write(shadow, OTHER_OFFSET, Amd64::BREAKPOINT.len()),
        ]
    );

    Ok(())
}

/// Verifies every view, GFN, and offset condition for event matching.
#[test]
fn contains_breakpoint_matches_software_event_view_gfn_and_ip_offset() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;

    assert!(interceptor.contains_breakpoint(&breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET)));

    for event in [
        breakpoint_event(OTHER_GFN, Some(VIEW), OFFSET),
        breakpoint_event(ORIGINAL_GFN, Some(OTHER_VIEW), OFFSET),
        breakpoint_event(ORIGINAL_GFN, Some(VIEW), OTHER_OFFSET),
        breakpoint_event(ORIGINAL_GFN, None, OFFSET),
    ] {
        assert!(!interceptor.contains_breakpoint(&event));
    }

    Ok(())
}

/// Verifies that non-breakpoint event reasons never match.
#[test]
fn contains_breakpoint_rejects_non_software_breakpoint_events() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    interceptor.insert_breakpoint(&vmi, address(ORIGINAL_GFN, OFFSET), VIEW)?;

    assert!(!interceptor.contains_breakpoint(&non_breakpoint_event(
        ORIGINAL_GFN,
        Some(VIEW),
        OFFSET
    )));

    Ok(())
}

/// Verifies that allocation failure leaves no state and permits retry.
#[test]
fn allocation_failure_leaves_no_page_or_mapping_and_can_retry() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    let address = address(ORIGINAL_GFN, OFFSET);
    vmi.driver().fail_on(Fault::Allocate);

    assert_injected_error(interceptor.insert_breakpoint(&vmi, address, VIEW));
    assert!(!vmi.driver().has_page(FIRST_SHADOW_GFN));
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert!(!interceptor.contains_breakpoint(&breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET)));

    assert_eq!(
        interceptor.insert_breakpoint(&vmi, address, VIEW)?,
        FIRST_SHADOW_GFN
    );

    Ok(())
}

/// Verifies cleanup and retry after every initial activation failure.
#[test]
fn activation_failure_frees_the_unregistered_shadow_and_can_retry() -> Result<(), VmiError> {
    for fault in [
        Fault::Read(ORIGINAL_GFN),
        Fault::Write(FIRST_SHADOW_GFN, 0),
        Fault::Change(VIEW, ORIGINAL_GFN, FIRST_SHADOW_GFN),
    ] {
        let vmi = test_vmi()?;
        let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
        let address = address(ORIGINAL_GFN, OFFSET);
        vmi.driver().fail_on(fault);

        assert_injected_error(interceptor.insert_breakpoint(&vmi, address, VIEW));
        assert!(!vmi.driver().has_page(FIRST_SHADOW_GFN));
        assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
        assert!(vmi.driver().calls().contains(&Call::Free(FIRST_SHADOW_GFN)));
        assert!(!interceptor.contains_breakpoint(&breakpoint_event(
            ORIGINAL_GFN,
            Some(VIEW),
            OFFSET
        )));

        assert_eq!(
            interceptor.insert_breakpoint(&vmi, address, VIEW)?,
            Gfn(FIRST_SHADOW_GFN.0 + 1)
        );
    }

    Ok(())
}

/// Verifies mapping rollback and retry after breakpoint installation failure.
#[test]
fn breakpoint_install_failure_rolls_back_mapping_and_can_retry() -> Result<(), VmiError> {
    for fault in [
        Fault::Read(FIRST_SHADOW_GFN),
        Fault::Write(FIRST_SHADOW_GFN, OFFSET),
    ] {
        let vmi = test_vmi()?;
        let original = vmi.driver().page(ORIGINAL_GFN);
        let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
        let address = address(ORIGINAL_GFN, OFFSET);
        vmi.driver().fail_on(fault);

        assert_injected_error(interceptor.insert_breakpoint(&vmi, address, VIEW));
        assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
        assert!(!interceptor.contains_breakpoint(&breakpoint_event(
            ORIGINAL_GFN,
            Some(VIEW),
            OFFSET
        )));

        let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
        assert_eq!(shadow, FIRST_SHADOW_GFN);
        assert_eq!(vmi.driver().allocation_count(), 1);
        assert_eq!(vmi.driver().page(shadow), with_breakpoint(original, OFFSET));
        assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));
    }

    Ok(())
}

/// Verifies that restoration failure leaves an active, retryable breakpoint.
#[test]
fn restore_write_failure_keeps_breakpoint_active_for_retry() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    let address = address(ORIGINAL_GFN, OFFSET);
    let event = breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().fail_on(Fault::Write(shadow, OFFSET));

    assert_injected_error(interceptor.remove_breakpoint(&vmi, address, VIEW));
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(original.clone(), OFFSET)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));
    assert!(interceptor.contains_breakpoint(&event));

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}

/// Verifies atomic state rollback when final view reset fails.
#[test]
fn view_reset_failure_restores_breakpoint_state_for_retry() -> Result<(), VmiError> {
    let vmi = test_vmi()?;
    let original = vmi.driver().page(ORIGINAL_GFN);
    let mut interceptor = Interceptor::<MockInterceptorDriver>::new();
    let address = address(ORIGINAL_GFN, OFFSET);
    let event = breakpoint_event(ORIGINAL_GFN, Some(VIEW), OFFSET);
    let shadow = interceptor.insert_breakpoint(&vmi, address, VIEW)?;
    vmi.driver().fail_on(Fault::Reset(VIEW, ORIGINAL_GFN));

    assert_injected_error(interceptor.remove_breakpoint(&vmi, address, VIEW));
    assert_eq!(
        vmi.driver().page(shadow),
        with_breakpoint(original.clone(), OFFSET)
    );
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), Some(shadow));
    assert!(interceptor.contains_breakpoint(&event));

    assert_eq!(
        interceptor.remove_breakpoint(&vmi, address, VIEW)?,
        Some(true)
    );
    assert_eq!(vmi.driver().page(shadow), original);
    assert_eq!(vmi.driver().mapping(VIEW, ORIGINAL_GFN), None);
    assert!(!interceptor.contains_breakpoint(&event));

    Ok(())
}
