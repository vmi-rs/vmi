//! Implementation of the [`define_events!`] macro.
//!
//! The macro consumes a user-facing DSL that names a flat list of kernel
//! events followed by zero or more grouped module event blocks, and expands
//! to:
//!
//! - A flat enum with fixed derives (`Debug, Clone, Copy, PartialEq, Eq,
//!   Hash`), with module groups flattened into top-level variants.
//! - An `impl ReactorEvent` block exposing `type Module = <M>` and the
//!   per-variant `METADATA` table.
//!
//! [`define_events!`]: super::super::define_events

/// Maps a single token tree to `()`, used to count variants at compile time.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_events_unit {
    ($_t:tt) => {
        ()
    };
}

/// Defines a [`ReactorEvent`] enum for the symbols monitored by a [`Reactor`].
///
/// # Usage
///
/// ```no_run
/// # use vmi_utils::reactor::{define_events, define_modules};
/// # define_modules! {
/// #     pub enum Module {
/// #         #[module(name = "netio.sys")]
/// #         NetioSys,
/// #
/// #         #[module(name = "ncrypt.dll", mode(user, process = "lsass.exe"))]
/// #         Ncrypt,
/// #     }
/// # }
/// define_events! {
///     /// Events monitored by the reactor.
///     pub enum Event in Module {
///         // Kernel events must be listed at the top, before any module group.
///         // The variant ident becomes the symbol name.
///         NtCreateFile,
///         NtWriteFile,
///
///         // `optional` lets the event be absent from the profile.
///         #[event(optional)]
///         NtRetiredSymbol,
///
///         // Module group. Every variant inside is tagged with
///         // `EventMetadata::module = Some(Module::NetioSys)`.
///         NetioSys {
///             KfdClassify,
///
///             /// Some kernels expose this under a slightly different
///             /// name - aliases are tried in declaration order.
///             #[event(alias = "KfdIsLayerEmpty_v2")]
///             KfdIsLayerEmpty,
///         },
///
///         // Multiple aliases and `optional` compose freely.
///         Ncrypt {
///             #[event(
///                 name = "SslGenerateSessionKeys",
///                 alias = ["SslGenerateSessionKeys_v2", "SslGenerateSessionKeysEx"],
///                 optional,
///             )]
///             GenerateSessionKeys,
///         },
///     }
/// }
/// ```
///
/// # Attributes
///
/// `#[event(...)]` on a variant is optional. Arguments are
/// position-independent:
///
/// - `name = "..."`: override the symbol name. Defaults to
///   `stringify!($variant)`.
/// - `alias = "..."` or `alias = ["...", "..."]`: alternate symbol
///   names tried in order when `name` is not present in the profile.
/// - `optional`: the event is allowed to be absent from the profile..
///
/// # Generated code
///
/// - The enum, with `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]`.
/// - An `impl ReactorEvent for $Enum` block exposing
///   `type Module = $Module` and the per-variant `METADATA` table.
///
/// # Ordering
///
/// All kernel events must precede any module group. A kernel event
/// after a group, or a group between two kernel events, is a compile
/// error.
///
/// [`ReactorEvent`]: super::super::ReactorEvent
/// [`Reactor`]: super::super::Reactor
#[doc(hidden)]
#[macro_export]
macro_rules! _private_define_events {
    //
    // Public entry.
    //
    // Captures the enum and its module reference, then kicks off the body
    // muncher in the `kernels` phase.
    //

    (
        $(#[$enum_attr:meta])*
        $vis:vis enum $name:ident in $module:ident {
            $($body:tt)*
        }
    ) => {
        $crate::_private_define_events! {
            @parse_body
            ctx { [$(#[$enum_attr])*] [$vis] [$name] [$module] }
            phase { kernels }
            remaining { $($body)* }
            events { }
        }
    };

    //
    // @parse_body - base case: empty body.
    //

    (
        @parse_body
        ctx $ctx:tt
        phase $phase:tt
        remaining { }
        events $events:tt
    ) => {
        $crate::_private_define_events! {
            @emit
            ctx $ctx
            events $events
        }
    };

    //
    // @parse_body - module group `Ident { ... },`.
    //
    // Matches before the kernel-event arms because both start with an
    // identifier. The trailing `{ ... }` disambiguates.
    //

    (
        @parse_body
        ctx $ctx:tt
        phase $phase:tt
        remaining {
            $gmod:ident { $($inner:tt)* }
            $(, $($outer_rest:tt)*)?
        }
        events $events:tt
    ) => {
        $crate::_private_define_events! {
            @process_group_inner
            ctx $ctx
            group_module { $gmod }
            inner { $($inner)* }
            outer { $($($outer_rest)*)? }
            events $events
        }
    };

    //
    // @parse_body - kernel event in `groups` phase: forbidden mixing.
    //

    (
        @parse_body
        ctx $ctx:tt
        phase { groups }
        remaining {
            $(#[$($vattr:tt)*])*
            $variant:ident
            $(, $($rest:tt)*)?
        }
        events $events:tt
    ) => {
        compile_error!(concat!(
            "kernel event `",
            stringify!($variant),
            "` cannot appear after a module group. \
             Move all kernel events above the first module group."
        ));
    };

    //
    // @parse_body - kernel event with trailing comma.
    //

    (
        @parse_body
        ctx $ctx:tt
        phase { kernels }
        remaining {
            $(#[$($vattr:tt)*])*
            $variant:ident,
            $($rest:tt)*
        }
        events $events:tt
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: event
            state: {
                ctx $ctx
                after_body { @parse_body ctx $ctx phase { kernels } remaining { $($rest)* } }
                module { }
                variant { $variant }
                events $events
            }
            pass: { }
            found: { }
            attrs: { $(#[$($vattr)*])* }
        }
    };

    //
    // @parse_body - kernel event with no trailing comma (last in body).
    //

    (
        @parse_body
        ctx $ctx:tt
        phase { kernels }
        remaining {
            $(#[$($vattr:tt)*])*
            $variant:ident
        }
        events $events:tt
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: event
            state: {
                ctx $ctx
                after_body { @parse_body ctx $ctx phase { kernels } remaining { } }
                module { }
                variant { $variant }
                events $events
            }
            pass: { }
            found: { }
            attrs: { $(#[$($vattr)*])* }
        }
    };

    //
    // @process_group_inner - all inner variants of the group consumed,
    // resume the outer body parser in `groups` phase.
    //

    (
        @process_group_inner
        ctx $ctx:tt
        group_module { $gmod:ident }
        inner { }
        outer { $($outer:tt)* }
        events $events:tt
    ) => {
        $crate::_private_define_events! {
            @parse_body
            ctx $ctx
            phase { groups }
            remaining { $($outer)* }
            events $events
        }
    };

    //
    // @process_group_inner - one variant of the group, with trailing comma.
    //

    (
        @process_group_inner
        ctx $ctx:tt
        group_module { $gmod:ident }
        inner {
            $(#[$($vattr:tt)*])*
            $variant:ident,
            $($rest:tt)*
        }
        outer $outer:tt
        events $events:tt
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: event
            state: {
                ctx $ctx
                after_body { @process_group_inner ctx $ctx group_module { $gmod } inner { $($rest)* } outer $outer }
                module { group $gmod }
                variant { $variant }
                events $events
            }
            pass: { }
            found: { }
            attrs: { $(#[$($vattr)*])* }
        }
    };

    //
    // @process_group_inner - one variant of the group, no trailing comma.
    //

    (
        @process_group_inner
        ctx $ctx:tt
        group_module { $gmod:ident }
        inner {
            $(#[$($vattr:tt)*])*
            $variant:ident
        }
        outer $outer:tt
        events $events:tt
    ) => {
        $crate::_private_split_reactor_attrs! {
            peel: event
            state: {
                ctx $ctx
                after_body { @process_group_inner ctx $ctx group_module { $gmod } inner { } outer $outer }
                module { group $gmod }
                variant { $variant }
                events $events
            }
            pass: { }
            found: { }
            attrs: { $(#[$($vattr)*])* }
        }
    };

    //
    // @after_split - empty `found:` means no `#[event(...)]` was supplied.
    // The variant ident becomes the symbol name (no alias, not optional).
    // This arm must precede the catch-all `found: { $($eargs:tt)* }` below.
    //
    // `name { }` is used for "no explicit name" - @event_name resolves it
    // to `stringify!($variant)` at emission time.
    //

    (
        @after_split
        state: {
            ctx $ctx:tt
            after_body $after:tt
            module $module:tt
            variant $variant:tt
            events $events:tt
        }
        pass: $pass:tt
        found: { }
    ) => {
        $crate::_private_define_events! {
            @finish_event
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name { }
            alias { [ ] }
            optional { false }
        }
    };

    //
    // @after_split - non-empty `found:` carries the captured `#[event(...)]`
    // arguments. Hand off to the per-arg parser.
    //

    (
        @after_split
        state: {
            ctx $ctx:tt
            after_body $after:tt
            module $module:tt
            variant $variant:tt
            events $events:tt
        }
        pass: $pass:tt
        found: { $($eargs:tt)* }
    ) => {
        $crate::_private_define_events! {
            @parse_event_args
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name { }
            alias { [ ] }
            optional { false }
            args { $($eargs)* }
        }
    };

    //
    // @parse_event_args - consume `name = "..."`.
    //

    (
        @parse_event_args
        ctx $ctx:tt
        after_body $after:tt
        module $module:tt
        variant $variant:tt
        events $events:tt
        pass $pass:tt
        name $_old_name:tt
        alias $alias:tt
        optional $optional:tt
        args { name = $name:literal $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_events! {
            @parse_event_args
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name { $name }
            alias $alias
            optional $optional
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_event_args - consume `alias = "x"` (single string).
    //

    (
        @parse_event_args
        ctx $ctx:tt
        after_body $after:tt
        module $module:tt
        variant $variant:tt
        events $events:tt
        pass $pass:tt
        name $name:tt
        alias $_old_alias:tt
        optional $optional:tt
        args { alias = $alias:literal $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_events! {
            @parse_event_args
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name $name
            alias { [ $alias ] }
            optional $optional
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_event_args - consume `alias = ["x", "y", ...]` (array form).
    //

    (
        @parse_event_args
        ctx $ctx:tt
        after_body $after:tt
        module $module:tt
        variant $variant:tt
        events $events:tt
        pass $pass:tt
        name $name:tt
        alias $_old_alias:tt
        optional $optional:tt
        args { alias = [ $($alias:literal),* $(,)? ] $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_events! {
            @parse_event_args
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name $name
            alias { [ $($alias),* ] }
            optional $optional
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_event_args - consume `optional` flag.
    //

    (
        @parse_event_args
        ctx $ctx:tt
        after_body $after:tt
        module $module:tt
        variant $variant:tt
        events $events:tt
        pass $pass:tt
        name $name:tt
        alias $alias:tt
        optional $_old_optional:tt
        args { optional $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_events! {
            @parse_event_args
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name $name
            alias $alias
            optional { true }
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_event_args - empty args, finalize the entry.
    //

    (
        @parse_event_args
        ctx $ctx:tt
        after_body $after:tt
        module $module:tt
        variant $variant:tt
        events $events:tt
        pass $pass:tt
        name $name:tt
        alias $alias:tt
        optional $optional:tt
        args { }
    ) => {
        $crate::_private_define_events! {
            @finish_event
            ctx $ctx
            after_body $after
            module $module
            variant $variant
            events $events
            pass $pass
            name $name
            alias $alias
            optional $optional
        }
    };

    //
    // @finish_event - append the parsed event to the accumulator and resume
    // the appropriate body parser.
    //

    (
        @finish_event
        ctx $ctx:tt
        after_body { $($after:tt)* }
        module $module:tt
        variant { $variant:ident }
        events { $($events:tt)* }
        pass { $($pass:tt)* }
        name $name:tt
        alias $alias:tt
        optional { $optional:tt }
    ) => {
        $crate::_private_define_events! {
            $($after)*
            events {
                $($events)*
                {
                    variant: $variant,
                    pass: [$($pass)*],
                    module: $module,
                    name: $name,
                    alias: $alias,
                    optional: $optional,
                }
            }
        }
    };

    //
    // @emit - all events collected, generate the enum and impl.
    //

    (
        @emit
        ctx { [$($eattr:tt)*] [$vis:vis] [$name:ident] [$module:ident] }
        events {
            $(
                {
                    variant: $variant:ident,
                    pass: [$($pass:tt)*],
                    module: $event_module:tt,
                    name: $event_name:tt,
                    alias: $event_alias:tt,
                    optional: $optional:tt,
                }
            )*
        }
    ) => {
        $($eattr)*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $(
                $($pass)*
                $variant,
            )*
        }

        impl $crate::reactor::ReactorEvent for $name {
            type Module = $module;

            const METADATA: &'static [$crate::reactor::EventMetadata<Self>] = &[
                $(
                    $crate::reactor::EventMetadata {
                        name: $crate::_private_define_events!(
                            @event_name $event_name $variant
                        ),
                        alias: $crate::_private_define_events!(
                            @event_alias $event_alias
                        ),
                        module: $crate::_private_define_events!(
                            @event_module $event_module $module
                        ),
                        event: Self::$variant,
                        optional: $optional,
                    },
                )*
            ];
        }
    };

    //
    // @event_name helpers - empty `{ }` means no explicit name was given,
    // so derive one from the variant ident. The empty arm must precede the
    // literal arm.
    //

    (@event_name { } $variant:ident) => {
        stringify!($variant)
    };

    (@event_name { $literal:literal } $variant:ident) => {
        $literal
    };

    //
    // @event_alias helper - unwrap `{ [ "x", "y", ... ] }` into `&["x", "y"]`.
    //

    (@event_alias { [ $($alias:literal),* $(,)? ] }) => {
        &[ $($alias),* ]
    };

    //
    // @event_module helpers - convert `module` tag to an Option.
    //

    (@event_module { } $module:ident) => {
        None
    };

    (@event_module { group $gmod:ident } $module:ident) => {
        Some($module::$gmod)
    };
}
