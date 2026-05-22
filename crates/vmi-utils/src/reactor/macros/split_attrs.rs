//! Shared attribute-splitter used by [`define_modules!`] and [`define_events!`].
//!
//! Both macros need to walk the attributes of a variant, peel off a single
//! reactor-specific attribute (`#[module(...)]` for modules, `#[event(...)]`
//! for events), and keep every other attribute on the variant. The walking
//! logic is identical apart from the path being peeled and where to return
//! control when the walk is finished.
//!
//! This helper consolidates the walk into one place. Callers tell it:
//!
//! - `peel:` - which reactor attribute path to recognize (`module` or `event`).
//! - `state:` - an opaque token tree threaded back unchanged when the walk
//!   completes. Each caller picks its own state shape.
//! - `attrs:` - the attribute stream to walk.
//!
//! When the walk finishes, the helper hands control back to the appropriate
//! parent macro through its `@after_split` arm. Callers seed `found:` with
//! an empty `{ }`; if the walk ends with `found:` still empty, the parent
//! arm knows no matching attribute was present.
//!
//! [`define_modules!`]: super::super::define_modules
//! [`define_events!`]: super::super::define_events

/// Walks a variant's attribute stream, peeling the single reactor-specific
/// attribute identified by `peel` and accumulating the rest into `pass`.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_split_reactor_attrs {
    //
    // Found `#[module(...)]` when peeling for modules.
    //

    (
        peel: module
        state: $state:tt
        pass: $pass:tt
        found: $_old:tt
        attrs: { #[module($($args:tt)*)] $($more:tt)* }
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: module
            state: $state
            pass: $pass
            found: { $($args)* }
            attrs: { $($more)* }
        }
    };

    //
    // Found `#[event(...)]` when peeling for events.
    //

    (
        peel: event
        state: $state:tt
        pass: $pass:tt
        found: $_old:tt
        attrs: { #[event($($args:tt)*)] $($more:tt)* }
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: event
            state: $state
            pass: $pass
            found: { $($args)* }
            attrs: { $($more)* }
        }
    };

    //
    // Any other attribute - append to `pass` verbatim.
    //
    // Matches after the path-specific arms above so that a `#[module(...)]`
    // or `#[event(...)]` that matches the active `peel` is never treated as
    // pass-through.
    //

    (
        peel: $peel:ident
        state: $state:tt
        pass: { $($pass:tt)* }
        found: $found:tt
        attrs: { #[$($other:tt)*] $($more:tt)* }
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: $peel
            state: $state
            pass: { $($pass)* #[$($other)*] }
            found: $found
            attrs: { $($more)* }
        }
    };

    //
    // No attrs left, hand control back to the modules macro.
    //

    (
        peel: module
        state: $state:tt
        pass: $pass:tt
        found: $found:tt
        attrs: { }
    ) => {
        $crate::_private_define_modules! {
            @after_split
            state: $state
            pass: $pass
            found: $found
        }
    };

    //
    // No attrs left, hand control back to the events macro.
    //

    (
        peel: event
        state: $state:tt
        pass: $pass:tt
        found: $found:tt
        attrs: { }
    ) => {
        $crate::_private_define_events! {
            @after_split
            state: $state
            pass: $pass
            found: $found
        }
    };
}
