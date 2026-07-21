use vmi_core::{AddressContext, View};

use super::{
    super::Breakpoint,
    mock::{OTHER_ROOT, OTHER_VA, ROOT, TEST_VA},
};

/// Verifies default metadata and local scope from the base builder.
#[test]
fn base_builder_uses_default_metadata() {
    let ctx = AddressContext::new(TEST_VA, ROOT);
    let breakpoint = Breakpoint::<(), ()>::from(Breakpoint::new(ctx, View(3)));

    assert_eq!(breakpoint.ctx(), ctx);
    assert_eq!(breakpoint.view(), View(3));
    assert!(!breakpoint.global());
    assert_eq!(breakpoint.key(), ());
    assert_eq!(breakpoint.tag(), ());
}

/// Verifies that global scope survives every builder transition.
#[test]
fn global_scope_survives_key_and_tag_builders() {
    let ctx = AddressContext::new(TEST_VA, ROOT);
    let breakpoint = Breakpoint::<u8, &str>::from(
        Breakpoint::new(ctx, View(4))
            .global()
            .with_key(7)
            .with_tag("entry"),
    );

    assert_eq!(breakpoint.ctx(), ctx);
    assert_eq!(breakpoint.view(), View(4));
    assert!(breakpoint.global());
    assert_eq!(breakpoint.key(), 7);
    assert_eq!(breakpoint.tag(), "entry");
}

/// Verifies equivalent output for both metadata-builder orders.
#[test]
fn key_and_tag_can_be_set_in_either_order() {
    let ctx = AddressContext::new(TEST_VA, ROOT);
    let key_first =
        Breakpoint::<u8, &str>::from(Breakpoint::new(ctx, View(5)).with_key(9).with_tag("target"));
    let tag_first =
        Breakpoint::<u8, &str>::from(Breakpoint::new(ctx, View(5)).with_tag("target").with_key(9));

    assert_eq!(key_first, tag_first);
}

/// Verifies that every breakpoint property participates in identity.
#[test]
fn breakpoint_identity_includes_context_view_scope_key_and_tag() {
    let base = Breakpoint::<u8, &str>::from(
        Breakpoint::new((TEST_VA, ROOT), View(1))
            .with_key(1)
            .with_tag("a"),
    );
    let variants = [
        Breakpoint::new((OTHER_VA, ROOT), View(1))
            .with_key(1)
            .with_tag("a")
            .into(),
        Breakpoint::new((TEST_VA, OTHER_ROOT), View(1))
            .with_key(1)
            .with_tag("a")
            .into(),
        Breakpoint::new((TEST_VA, ROOT), View(2))
            .with_key(1)
            .with_tag("a")
            .into(),
        Breakpoint::new((TEST_VA, ROOT), View(1))
            .global()
            .with_key(1)
            .with_tag("a")
            .into(),
        Breakpoint::new((TEST_VA, ROOT), View(1))
            .with_key(2)
            .with_tag("a")
            .into(),
        Breakpoint::new((TEST_VA, ROOT), View(1))
            .with_key(1)
            .with_tag("b")
            .into(),
    ];

    for variant in variants {
        assert_ne!(base, variant);
    }
}
