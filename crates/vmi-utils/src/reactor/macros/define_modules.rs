//! Implementation of the [`define_modules!`] macro.
//!
//! The macro consumes a user-facing DSL describing a module enum and
//! optional resolver / cache wrapper structs, and expands to:
//!
//! - The enum with fixed derives (`Debug, Clone, Copy, PartialEq, Eq, Hash`).
//! - A blanket `impl<__Os: VmiOs + 'static> ReactorModule<__Os>` block
//!   with `METADATA`, `KERNEL_SLOT`, `slot`.
//! - If `#[resolver]` is present, a resolver wrapper parameterized over
//!   `Os` with `with_kernel`, `with_module`, `into_events`.
//! - If `#[resolver]` and `#[cache]` are both present, a symbol cache
//!   struct plus a `resolve` method on the resolver, available only when
//!   `Os = WindowsOs<Driver>`.
//!
//! [`define_modules!`]: super::super::define_modules

/// Maps a single token tree to `()`. Used to count repetitions at compile time
/// by emitting `<[()]>::len(&[ () , () , ... ])`.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_modules_unit {
    ($_t:tt) => {
        ()
    };
}

/// Defines a [`ReactorModule`] enum for the modules monitored by a [`Reactor`].
///
/// # Usage
///
/// ```no_run
/// # use vmi_core::{VmiError, driver::VmiRead};
/// # use vmi_os_windows::{ArchAdapter, WindowsOs, WindowsProcess};
/// # use vmi_utils::reactor::define_modules;
/// #
/// # fn in_lsass<Driver>(_p: &WindowsProcess<Driver>) -> Result<bool, VmiError>
/// # where
/// #     Driver: VmiRead,
/// #     Driver::Architecture: ArchAdapter<Driver>,
/// # { Ok(true) }
/// #
/// define_modules! {
///     /// Modules monitored by the reactor.
///     #[os(<Driver: VmiRead> WindowsOs<Driver> where Driver::Architecture: ArchAdapter<Driver>)]
///     pub enum Module {
///         // Kernel-mode driver. `mode = kernel` is the default.
///         #[module(name = "netio.sys")]
///         NetioSys,
///
///         // Kernel-mode module mapped only in certain processes.
///         // `win32k.sys` is not present in every address space, so pin
///         // it to a process that maps it.
///         #[module(name = "win32k.sys", mode = kernel, process = "csrss.exe")]
///         Win32kInCsrss,
///
///         // User-mode DLL with no process filter. The resolver picks
///         // the first process that maps the image.
///         #[module(name = "ntdll.dll", mode = user)]
///         NtDll,
///
///         // User-mode DLL pinned to a process by exact image name
///         // (case-insensitive). `mode` and `process` are order-independent.
///         #[module(name = "ncrypt.dll", process = "lsass.exe", mode = user)]
///         NcryptInLsass,
///
///         // User-mode DLL pinned by a caller-supplied predicate.
///         #[module(name = "user32.dll", mode = user, process = in_lsass)]
///         User32InLsass,
///
///         // `optional` lets the module be absent from the guest.
///         // The corresponding events resolve to `Ok(None)` and are
///         // dropped from the event vector.
///         #[module(name = "msmpeng.exe", mode = user, optional)]
///         Defender,
///     }
///
///     // Emit `ModuleResolver` - a typed resolver wrapper.
///     #[resolver]
///     pub struct ModuleResolver;
///
///     // Emit `SymbolCache` - a profile cache backing `.resolve(...)`.
///     // Requires `#[resolver]`. The two markers may appear in either
///     // order.
///     #[cache]
///     pub struct SymbolCache;
/// }
/// ```
///
/// # Attributes
///
/// - `#[os(...)]` on the enum: anchors the generated `ReactorModule`
///   impl to a specific OS family. Two shapes are accepted:
///
///   - `#[os(<G...> $os_ty where $bounds)]` - generics and where-bounds
///     spelled by the caller and emitted verbatim, e.g.
///     `#[os(<Driver: VmiRead> WindowsOs<Driver> where Driver::Architecture: ArchAdapter<Driver>)]`.
///   - `#[os($os_ty)]` - no generic parameters, the impl binds to a
///     concrete type or alias, e.g. `#[os(WindowsOs<VmiXenDriver<Amd64>>)]`.
///
///   Omitting `#[os(...)]` emits a blanket
///   `impl<Os: VmiOs + 'static> ReactorModule<Os>` covering every OS
///   family. Predicates passed to `process = ...` must then be
///   `Os`-generic.
///
/// - `#[module(...)]` on each variant: required. Arguments are
///   position-independent.
///
///   - `name = "..."` (required): image filename, e.g. `"ntdll.dll"`.
///   - `mode = kernel` (default): kernel address space.
///   - `mode = user`: user-mode process address space.
///   - `process = ...` (optional): pin the module to a process, in either
///     mode. Accepts either a `"literal"` matched case-insensitively
///     against the image name, or a predicate `path` (a bare ident or a
///     fully qualified path) with signature
///     `fn(&Os::Process<'_>) -> Result<bool, VmiError>`. A kernel image
///     mapped only in some processes (e.g. `win32k.sys`) uses this to
///     select where to resolve.
///   - `optional`: the module is allowed to be absent from the guest.
///
/// - `#[resolver] $vis struct $Name;` (optional): emit the resolver
///   wrapper named `$Name`. Rustdoc and other attributes on the marker
///   struct are not permitted.
///
/// - `#[cache] $vis struct $Name;` (optional): emit a profile cache
///   named `$Name`. Requires `#[resolver]`. Backs the resolver's
///   Windows-anchored `.resolve(...)`.
///
/// # Generated code
///
/// - The enum, with `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]`.
/// - One `impl ReactorModule<Os> for $Enum` block, blanket or anchored
///   depending on `#[os(...)]`.
/// - If `#[resolver]` is present: a `$Resolver<'a, Os>` struct with
///   `default()`, `with_kernel`, `with_module`, `with_module_in_process`,
///   and `into_events()`.
/// - If `#[resolver]` and `#[cache]` are both present: a `$Cache` struct
///   (an array of profiles) and a
///   `.resolve(session, isr, &mut cache) -> Result<Self, VmiError>`.
///
/// [`ReactorModule`]: super::super::ReactorModule
/// [`Reactor`]: super::super::Reactor
#[doc(hidden)]
#[macro_export]
macro_rules! _private_define_modules {
    //
    // Public entry.
    //
    // Captures the enum and its trailing resolver / cache markers as tt streams
    // so the optional `#[os(...)]` attribute (which carries a non-literal type
    // and so cannot match `:meta`) can be peeled by `@walk_enum_attrs` before
    // variant processing begins.
    //

    (
        $(#[$($enum_attr:tt)*])*
        $vis:vis enum $name:ident {
            $(
                $(#[$($vattr:tt)*])*
                $variant:ident
            ),* $(,)?
        }
        $($trailing:tt)*
    ) => {
        $crate::_private_define_modules! {
            @walk_enum_attrs
            attrs: { $( #[$($enum_attr)*] )* }
            pass:  { }
            os:    { }
            tail:  {
                vis: [$vis]
                name: [$name]
                trailing: [$($trailing)*]
                variants: [ $( { [$(#[$($vattr)*])*] $variant } )* ]
            }
        }
    };

    //
    // @walk_enum_attrs - peel a single `#[os(...)]` and pass everything else
    // through unchanged. A second `#[os(...)]` is a compile_error!.
    //

    (
        @walk_enum_attrs
        attrs: { #[os($($args:tt)*)] $($more:tt)* }
        pass:  $pass:tt
        os:    { }
        tail:  $tail:tt
    ) => {
        $crate::_private_define_modules! {
            @walk_enum_attrs
            attrs: { $($more)* }
            pass:  $pass
            os:    { $($args)* }
            tail:  $tail
        }
    };

    (
        @walk_enum_attrs
        attrs: { #[os($($args:tt)*)] $($more:tt)* }
        pass:  $pass:tt
        os:    { $($_old:tt)+ }
        tail:  $tail:tt
    ) => {
        compile_error!("`#[os(...)]` may only appear once on the enum");
    };

    (
        @walk_enum_attrs
        attrs: { #[$($other:tt)*] $($more:tt)* }
        pass:  { $($pass:tt)* }
        os:    $os:tt
        tail:  $tail:tt
    ) => {
        $crate::_private_define_modules! {
            @walk_enum_attrs
            attrs: { $($more)* }
            pass:  { $($pass)* #[$($other)*] }
            os:    $os
            tail:  $tail
        }
    };

    (
        @walk_enum_attrs
        attrs: { }
        pass:  { $($pass:tt)* }
        os:    $os:tt
        tail:  {
            vis: [$vis:vis]
            name: [$name:ident]
            trailing: [$($trailing:tt)*]
            variants: [ $({ [$($vattr:tt)*] $variant:ident })* ]
        }
    ) => {
        $crate::_private_define_modules! {
            @process_variants
            ctx { [$($pass)*] [$vis] [$name] [$($trailing)*] [$os] }
            input { $( { [$($vattr)*] $variant } )* }
            output { }
        }
    };

    //
    // @process_variants - base case: no more input variants.
    //

    (
        @process_variants
        ctx $ctx:tt
        input { }
        output $output:tt
    ) => {
        $crate::_private_define_modules! {
            @finalize
            ctx $ctx
            output $output
        }
    };

    //
    // @process_variants - recursive: pull the next variant and hand its
    // attributes to the shared splitter.
    //

    (
        @process_variants
        ctx $ctx:tt
        input { { [ $($attrs:tt)* ] $variant:ident } $($rest:tt)* }
        output $output:tt
    ) => {
        // `found:` starts empty - the splitter fills it in when it
        // encounters `#[module(...)]`. An empty `found:` after the walk
        // therefore means "no module attribute was supplied."
        $crate::_private_split_reactor_attrs! {
            peel: module
            state: {
                ctx $ctx
                input { $($rest)* }
                output $output
                variant { $variant }
            }
            pass: { }
            found: { }
            attrs: { $($attrs)* }
        }
    };

    //
    // @after_split - empty `found:` means no `#[module(...)]` was supplied.
    // This arm must precede the catch-all `found: { $($margs:tt)* }` arm
    // below so the empty case is preferred.
    //

    (
        @after_split
        state: {
            ctx $ctx:tt
            input $input:tt
            output $output:tt
            variant { $variant:ident }
        }
        pass: $pass:tt
        found: { }
    ) => {
        compile_error!(concat!(
            "module variant `", stringify!($variant), "` is missing `#[module(name = \"...\")]`"
        ));
    };

    //
    // @after_split - non-empty `found:` carries the captured
    // `#[module(...)]` arguments. Dispatch to the per-arg parser.
    //

    (
        @after_split
        state: {
            ctx $ctx:tt
            input $input:tt
            output $output:tt
            variant $variant:tt
        }
        pass: $pass:tt
        found: { $($margs:tt)* }
    ) => {
        // `name { }` starts empty for the same reason as `found:` above
        // - an empty `name {}` after parsing means the caller forgot
        // `name = "..."`.
        //
        // `mode { kernel }` is the default when no `mode = ...` is given.
        // `process { }` stays empty until a `process = ...` fills it, the
        // same empty-means-absent convention `name { }` uses above.
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name { }
            mode { kernel }
            process { }
            optional { false }
            args { $($margs)* }
        }
    };

    //
    // @parse_module_args - consume `name = "..."` (optionally followed by `, ...`).
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $_old_name:tt
        mode $mode:tt
        process $process:tt
        optional $opt:tt
        args { name = $name:literal $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name { $name }
            mode $mode
            process $process
            optional $opt
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_module_args - consume `mode = kernel` or `mode = user`.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $_old_mode:tt
        process $process:tt
        optional $opt:tt
        args { mode = $mode:ident $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode { $mode }
            process $process
            optional $opt
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_module_args - consume `process = "..."` (literal image name).
    // A literal is a single fragment, so it composes with the optional
    // trailing comma directly. This arm must precede the predicate arm
    // below, whose token scanner would otherwise swallow the literal.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        process $_old_process:tt
        optional $opt:tt
        args { process = $proc:literal $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            process { name $proc }
            optional $opt
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_module_args - consume `process = <path>` (predicate). The value
    // can be several tokens (`self::match`), and a greedy `$($path:tt)+`
    // before an optional trailing comma is a local ambiguity, so hand the
    // remaining args to `@scan_predicate`, which peels path tokens up to the
    // next top-level comma.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        process $_old_process:tt
        optional $opt:tt
        args { process = $($rest:tt)+ }
    ) => {
        $crate::_private_define_modules! {
            @scan_predicate
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            optional $opt
            path { }
            args { $($rest)+ }
        }
    };

    //
    // @scan_predicate - collect the tokens of a `process = <path>` predicate
    // into `path { ... }`. A top-level comma ends the predicate and resumes
    // `@parse_module_args`. This comma arm must precede the token arm below,
    // since a comma also matches `$next:tt`.
    //

    (
        @scan_predicate
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        optional $opt:tt
        path { $($path:tt)* }
        args { , $($rest:tt)* }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            process { predicate $($path)* }
            optional $opt
            args { $($rest)* }
        }
    };

    //
    // @scan_predicate - end of args: the predicate runs to the end.
    //

    (
        @scan_predicate
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        optional $opt:tt
        path { $($path:tt)* }
        args { }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            process { predicate $($path)* }
            optional $opt
            args { }
        }
    };

    //
    // @scan_predicate - fold one non-comma token into the path accumulator.
    //

    (
        @scan_predicate
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        optional $opt:tt
        path { $($path:tt)* }
        args { $next:tt $($rest:tt)* }
    ) => {
        $crate::_private_define_modules! {
            @scan_predicate
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            optional $opt
            path { $($path)* $next }
            args { $($rest)* }
        }
    };

    //
    // @parse_module_args - consume `optional` flag.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant $variant:tt
        pass $pass:tt
        name $name:tt
        mode $mode:tt
        process $process:tt
        optional $_old_opt:tt
        args { optional $(, $($rest:tt)*)? }
    ) => {
        $crate::_private_define_modules! {
            @parse_module_args
            ctx $ctx
            input $input
            output $output
            variant $variant
            pass $pass
            name $name
            mode $mode
            process $process
            optional { true }
            args { $($($rest)*)? }
        }
    };

    //
    // @parse_module_args - done with no `name = "..."` ever consumed:
    // the `name { }` slot is still empty. This arm must precede the
    // success arm below.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output $output:tt
        variant { $variant:ident }
        pass $pass:tt
        name { }
        mode $mode:tt
        process $process:tt
        optional $opt:tt
        args { }
    ) => {
        compile_error!(concat!(
            "module variant `", stringify!($variant), "` is missing `name = \"...\"` in `#[module(...)]`"
        ));
    };

    //
    // @parse_module_args - done, append the variant to the output.
    //

    (
        @parse_module_args
        ctx $ctx:tt
        input $input:tt
        output { $($out:tt)* }
        variant { $variant:ident }
        pass { $($pass:tt)* }
        name { $mod_name:literal }
        mode { $($mode:tt)* }
        process { $($process:tt)* }
        optional { $opt:tt }
        args { }
    ) => {
        $crate::_private_define_modules! {
            @process_variants
            ctx $ctx
            input $input
            output {
                $($out)*
                {
                    variant: $variant,
                    pass: [$($pass)*],
                    name: $mod_name,
                    mode: { $($mode)* },
                    process: { $($process)* },
                    optional: $opt,
                }
            }
        }
    };

    //
    // @finalize - all variants are processed. Dispatch on the trailing markers.
    //

    // `#[resolver] ...; #[cache] ...;`
    (
        @finalize
        ctx {
            [$($eattr:tt)*]
            [$vis:vis]
            [$name:ident]
            [
                #[resolver] $rvis:vis struct $resolver:ident;
                #[cache]    $cvis:vis struct $cache:ident;
            ]
            [$os:tt]
        }
        output $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit
            attrs: [$($eattr)*] vis: [$vis] name: [$name] os: $os
            variants: $variants
            resolver: { yes $rvis $resolver }
            cache:    { yes $cvis $cache }
        }
    };

    // `#[cache] ...; #[resolver] ...;`
    (
        @finalize
        ctx {
            [$($eattr:tt)*]
            [$vis:vis]
            [$name:ident]
            [
                #[cache]    $cvis:vis struct $cache:ident;
                #[resolver] $rvis:vis struct $resolver:ident;
            ]
            [$os:tt]
        }
        output $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit
            attrs: [$($eattr)*] vis: [$vis] name: [$name] os: $os
            variants: $variants
            resolver: { yes $rvis $resolver }
            cache:    { yes $cvis $cache }
        }
    };

    // `#[resolver] ...;` only.
    (
        @finalize
        ctx {
            [$($eattr:tt)*]
            [$vis:vis]
            [$name:ident]
            [
                #[resolver] $rvis:vis struct $resolver:ident;
            ]
            [$os:tt]
        }
        output $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit
            attrs: [$($eattr)*] vis: [$vis] name: [$name] os: $os
            variants: $variants
            resolver: { yes $rvis $resolver }
            cache:    { no }
        }
    };

    // `#[cache] ...;` only - error.
    (
        @finalize
        ctx {
            [$($eattr:tt)*]
            [$vis:vis]
            [$name:ident]
            [
                #[cache] $cvis:vis struct $cache:ident;
            ]
            [$os:tt]
        }
        output $variants:tt
    ) => {
        compile_error!("`#[cache]` requires `#[resolver]`");
    };

    // No trailing markers.
    (
        @finalize
        ctx {
            [$($eattr:tt)*]
            [$vis:vis]
            [$name:ident]
            [ ]
            [$os:tt]
        }
        output $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit
            attrs: [$($eattr)*] vis: [$vis] name: [$name] os: $os
            variants: $variants
            resolver: { no }
            cache:    { no }
        }
    };

    //
    // @emit - generate the enum and dispatch to the appropriate impl emitter
    // based on whether `#[os(...)]` was provided.
    //

    (
        @emit
        attrs: [$($eattr:tt)*]
        vis:   [$vis:vis]
        name:  [$name:ident]
        os:    $os:tt
        variants: {
            $(
                {
                    variant: $variant:ident,
                    pass: [$($pass:tt)*],
                    name: $mod_name:literal,
                    mode: { $($mode:tt)* },
                    process: { $($process:tt)* },
                    optional: $opt:tt,
                }
            )*
        }
        resolver: $resolver:tt
        cache:    $cache:tt
    ) => {
        $($eattr)*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $(
                $($pass)*
                $variant,
            )*
        }

        $crate::_private_define_modules! {
            @emit_impl
            name: [$name]
            os:   $os
            variants: {
                $(
                    {
                        variant: $variant,
                        name: $mod_name,
                        mode: { $($mode)* },
                        process: { $($process)* },
                        optional: $opt,
                    }
                )*
            }
        }

        $crate::_private_define_modules! {
            @emit_resolver
            name: [$name]
            variants: { $( { variant: $variant, name: $mod_name, optional: $opt } )* }
            resolver: $resolver
            cache:    $cache
        }
    };

    //
    // @emit_impl - blanket case: `#[os(...)]` was omitted. Emits one impl over
    // `__Os: VmiOs + 'static`, so the enum serves every OS. Predicates passed
    // to `process = ...` must therefore be Os-generic.
    //
    // Predicates are turbofished with `__Os` because Rust cannot normalize the
    // abstract `__Os::Process<'_>` projection during dyn-Fn coercion, so it
    // cannot infer the predicate's generic from the expected type alone.
    //

    (
        @emit_impl
        name: [$name:ident]
        os:   { }
        variants: {
            $(
                {
                    variant: $variant:ident,
                    name: $mod_name:literal,
                    mode: { $($mode:tt)* },
                    process: { $($process:tt)* },
                    optional: $opt:tt,
                }
            )*
        }
    ) => {
        impl<__Os> $crate::reactor::ReactorModule<__Os> for $name
        where
            __Os: $crate::reactor::macros::__private::vmi_core::VmiOs + 'static,
        {
            const METADATA: &'static [$crate::reactor::ModuleMetadata<Self, __Os>] = &[
                $crate::reactor::ModuleMetadata {
                    name: "kernel",
                    process: ::std::option::Option::None,
                    module: ::std::option::Option::None,
                    mode: $crate::reactor::ModuleMode::Kernel,
                    optional: true,
                },
                $(
                    $crate::reactor::ModuleMetadata {
                        name: $mod_name,
                        process: $crate::_private_define_modules!(
                            @process_expr { $($process)* } turbofish: { ::<__Os> }
                        ),
                        module: ::std::option::Option::Some(Self::$variant),
                        mode: $crate::_private_define_modules!(
                            @mode_expr { $($mode)* }
                        ),
                        optional: $opt,
                    },
                )*
            ];

            const KERNEL_SLOT: usize = 0;

            fn slot(self) -> usize {
                self as usize + 1
            }
        }
    };

    //
    // @emit_impl - os-anchored case, with generic params. The impl signature is
    // spelled by the user via `#[os(<G...> OsTy where bounds...)]` and emitted
    // verbatim, anchoring the impl to a specific OS family.
    //
    // Generics are parsed structurally (per-param `:ident` with an optional
    // single-`:ident` bound) so angle brackets do not cause local ambiguity.
    // Complex bounds (`VmiRead<X>`, `Driver::Architecture: ArchAdapter<Driver>`)
    // belong in the `where` clause.
    //
    // This arm must precede the no-generics arm below - an input that begins
    // with `<` would otherwise be ambiguous between starting a generics list
    // and starting an HRTB-like `:ty` in the no-generics arm.
    //

    (
        @emit_impl
        name: [$name:ident]
        os:   {
            < $( $g_param:ident $( : $g_bound:ident )? ),+ >
            $os_ty:ty
            $( where $($bounds:tt)* )?
        }
        variants: $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit_impl_anchored
            name: [$name]
            impl_generics: [ $( $g_param $( : $g_bound )? ),+ ]
            os_ty: [$os_ty]
            where_bounds: [ $( $($bounds)* )? ]
            variants: $variants
        }
    };

    //
    // @emit_impl - os-anchored case, no generic params. The impl is bound to a
    // concrete OS type (e.g. `WindowsOs<VmiXenDriver<Amd64>>`) or a type alias.
    //

    (
        @emit_impl
        name: [$name:ident]
        os:   {
            $os_ty:ty
            $( where $($bounds:tt)* )?
        }
        variants: $variants:tt
    ) => {
        $crate::_private_define_modules! {
            @emit_impl_anchored
            name: [$name]
            impl_generics: [ ]
            os_ty: [$os_ty]
            where_bounds: [ $( $($bounds)* )? ]
            variants: $variants
        }
    };

    //
    // @emit_impl_anchored - shared emit for both anchored arms above. Receives
    // already-extracted generics, os type, and where bounds, and writes one
    // `impl ... ReactorModule<OsTy> for $name { ... }` block.
    //

    (
        @emit_impl_anchored
        name: [$name:ident]
        impl_generics: [ $($impl_generics:tt)* ]
        os_ty: [$os_ty:ty]
        where_bounds: [ $($bounds:tt)* ]
        variants: {
            $(
                {
                    variant: $variant:ident,
                    name: $mod_name:literal,
                    mode: { $($mode:tt)* },
                    process: { $($process:tt)* },
                    optional: $opt:tt,
                }
            )*
        }
    ) => {
        impl<$($impl_generics)*> $crate::reactor::ReactorModule<$os_ty> for $name
        where
            $($bounds)*
        {
            const METADATA: &'static [$crate::reactor::ModuleMetadata<Self, $os_ty>] = &[
                $crate::reactor::ModuleMetadata {
                    name: "kernel",
                    process: ::std::option::Option::None,
                    module: ::std::option::Option::None,
                    mode: $crate::reactor::ModuleMode::Kernel,
                    optional: true,
                },
                $(
                    $crate::reactor::ModuleMetadata {
                        name: $mod_name,
                        process: $crate::_private_define_modules!(
                            @process_expr { $($process)* } turbofish: { }
                        ),
                        module: ::std::option::Option::Some(Self::$variant),
                        mode: $crate::_private_define_modules!(
                            @mode_expr { $($mode)* }
                        ),
                        optional: $opt,
                    },
                )*
            ];

            const KERNEL_SLOT: usize = 0;

            fn slot(self) -> usize {
                self as usize + 1
            }
        }
    };

    //
    // @mode_expr - render a `ModuleMode` value from the parsed `mode { ... }`
    // accumulator, a single `kernel` or `user` keyword.
    //

    (@mode_expr { kernel }) => {
        $crate::reactor::ModuleMode::Kernel
    };

    (@mode_expr { user }) => {
        $crate::reactor::ModuleMode::User
    };

    //
    // @process_expr - render the `Option<ModuleProcessFilter<Os>>` from the
    // parsed `process { ... }` accumulator. An empty accumulator means no
    // filter. `name <literal>` and `predicate <path>` carry the two filter
    // kinds. Both kernel and user modules may pin a process. win32k.sys, for
    // instance, is a kernel image mapped only in the processes that use it.
    //
    // The `turbofish` parameter is appended verbatim after the predicate path
    // so the blanket emitter can pass `::<__Os>` to make the predicate's
    // generic explicit (needed because Rust cannot normalize the abstract
    // `__Os::Process<'_>` projection during dyn-Fn coercion). Anchored
    // emitters pass an empty turbofish - the impl's concrete bounds let
    // inference resolve the predicate's generic.
    //

    (@process_expr { } turbofish: $tf:tt) => {
        ::std::option::Option::None
    };

    (@process_expr { name $name:literal } turbofish: $tf:tt) => {
        ::std::option::Option::Some(
            $crate::reactor::ModuleProcessFilter::Name($name),
        )
    };

    (@process_expr { predicate $($path:tt)+ } turbofish: { $($tf:tt)* }) => {
        ::std::option::Option::Some(
            $crate::reactor::ModuleProcessFilter::Predicate(&$($path)+ $($tf)*),
        )
    };

    //
    // @emit_resolver - nothing when no `#[resolver]` is requested.
    //

    (
        @emit_resolver
        name: [$name:ident]
        variants: $variants:tt
        resolver: { no }
        cache:    { no }
    ) => { };

    //
    // @emit_resolver - resolver only (no cache).
    //

    (
        @emit_resolver
        name: [$name:ident]
        variants: {
            $( { variant: $variant:ident, name: $mod_name:literal, optional: $opt:tt } )*
        }
        resolver: { yes $rvis:vis $resolver:ident }
        cache:    { no }
    ) => {
        $crate::_private_define_modules! {
            @emit_resolver_struct
            name: [$name]
            variants: { $( { variant: $variant, name: $mod_name, optional: $opt } )* }
            resolver: { $rvis $resolver }
        }
    };

    //
    // @emit_resolver - resolver and cache.
    //

    (
        @emit_resolver
        name: [$name:ident]
        variants: {
            $( { variant: $variant:ident, name: $mod_name:literal, optional: $opt:tt } )*
        }
        resolver: { yes $rvis:vis $resolver:ident }
        cache:    { yes $cvis:vis $cache:ident }
    ) => {
        $crate::_private_define_modules! {
            @emit_resolver_struct
            name: [$name]
            variants: { $( { variant: $variant, name: $mod_name, optional: $opt } )* }
            resolver: { $rvis $resolver }
        }

        #[doc = concat!(
            "Cache for resolved symbol entries of `", stringify!($name), "`.\n\n",
            "Slot 0 is reserved for the kernel. The remaining slots correspond to ",
            "the modules of the enum, indexed by `slot()`."
        )]
        $cvis struct $cache {
            __inner: [
                ::std::option::Option<
                    $crate::reactor::macros::__private::isr_cache::Entry
                >;
                1 + <[()]>::len(&[ $( $crate::_private_modules_unit!($variant) ),* ])
            ],
        }

        impl ::std::default::Default for $cache {
            fn default() -> Self {
                Self {
                    __inner: [
                        const { ::std::option::Option::None };
                        1 + <[()]>::len(&[ $( $crate::_private_modules_unit!($variant) ),* ])
                    ],
                }
            }
        }

        #[allow(dead_code)]
        impl<'a, __Driver> $resolver<'a, $crate::reactor::macros::__private::vmi_os_windows::WindowsOs<__Driver>>
        where
            __Driver: $crate::reactor::macros::__private::vmi_core::driver::VmiFullDriver,
            __Driver::Architecture:
                $crate::reactor::macros::__private::vmi_os_windows::ArchAdapter<__Driver> +
                $crate::resolver::ArchAdapter<__Driver>,
        {
            /// Resolves the kernel and every module that has not been pre-populated.
            pub fn resolve(
                mut self,
                session: &$crate::reactor::macros::__private::vmi_core::VmiSession<
                    $crate::reactor::macros::__private::vmi_os_windows::WindowsOs<__Driver>
                >,
                isr: &$crate::reactor::macros::__private::isr_cache::IsrCache,
                entries: &'a mut $cache,
            ) -> ::std::result::Result<
                Self,
                $crate::reactor::macros::__private::vmi_core::VmiError,
            > {
                $crate::reactor::macros::__private::resolve_modules::<__Driver, $name>(
                    session,
                    isr,
                    entries.__inner.as_mut_slice(),
                    self.__inner.as_mut_slice(),
                )?;

                ::std::result::Result::Ok(self)
            }
        }
    };

    //
    // @emit_resolver_struct - shared resolver struct + Default + builder methods.
    //

    (
        @emit_resolver_struct
        name: [$name:ident]
        variants: {
            $( { variant: $variant:ident, name: $mod_name:literal, optional: $opt:tt } )*
        }
        resolver: { $rvis:vis $resolver:ident }
    ) => {
        #[doc = concat!(
            "Table of resolved modules for `", stringify!($name), "`.\n\n",
            "Slot 0 is reserved for the kernel; the remaining slots correspond to ",
            "the variants of the enum, indexed by `slot()`.\n\n",
            "The `Os` parameter is locked when `.resolve(...)` is called against a ",
            "concrete `VmiSession<Os>`; before that point inference will leave it open."
        )]
        $rvis struct $resolver<'a, __Os>
        where
            __Os: $crate::reactor::macros::__private::vmi_core::VmiOs + 'static,
        {
            __inner: [
                ::std::option::Option<$crate::reactor::ResolvedModule<'a>>;
                1 + <[()]>::len(&[ $( $crate::_private_modules_unit!($variant) ),* ])
            ],
            __marker: ::std::marker::PhantomData<fn() -> __Os>,
        }

        impl<'a, __Os> ::std::default::Default for $resolver<'a, __Os>
        where
            __Os: $crate::reactor::macros::__private::vmi_core::VmiOs + 'static,
        {
            fn default() -> Self {
                Self {
                    __inner: [
                        const { ::std::option::Option::None };
                        1 + <[()]>::len(&[ $( $crate::_private_modules_unit!($variant) ),* ])
                    ],
                    __marker: ::std::marker::PhantomData,
                }
            }
        }

        #[allow(dead_code)]
        impl<'a, __Os> $resolver<'a, __Os>
        where
            __Os: $crate::reactor::macros::__private::vmi_core::VmiOs + 'static,
            $name: $crate::reactor::ReactorModule<__Os>,
        {
            /// Stores a pre-resolved kernel entry.
            pub fn with_kernel(
                mut self,
                base_address: $crate::reactor::macros::__private::vmi_core::Va,
                profile: impl ::std::convert::Into<$crate::reactor::ProfileRef<'a>>,
            ) -> Self {
                let profile = profile.into();
                self.__inner[<$name as $crate::reactor::ReactorModule<__Os>>::KERNEL_SLOT] =
                    ::std::option::Option::Some(
                        $crate::reactor::ResolvedModule { process: None, base_address, profile },
                    );
                self
            }

            /// Stores a pre-resolved entry for a module.
            pub fn with_module(
                mut self,
                module: $name,
                base_address: $crate::reactor::macros::__private::vmi_core::Va,
                profile: impl ::std::convert::Into<$crate::reactor::ProfileRef<'a>>,
            ) -> Self {
                let profile = profile.into();
                let slot = <$name as $crate::reactor::ReactorModule<__Os>>::slot(module);
                self.__inner[slot] = ::std::option::Option::Some(
                    $crate::reactor::ResolvedModule { process: None, base_address, profile },
                );
                self
            }

            /// Stores a pre-resolved entry for a module in a specific process.
            pub fn with_module_in_process(
                mut self,
                module: $name,
                process: $crate::reactor::macros::__private::vmi_core::os::ProcessObject,
                base_address: $crate::reactor::macros::__private::vmi_core::Va,
                profile: impl ::std::convert::Into<$crate::reactor::ProfileRef<'a>>,
            ) -> Self {
                let profile = profile.into();
                let slot = <$name as $crate::reactor::ReactorModule<__Os>>::slot(module);
                self.__inner[slot] = ::std::option::Option::Some(
                    $crate::reactor::ResolvedModule { process: Some(process), base_address, profile },
                );
                self
            }

            /// Resolves the events declared against this module enum.
            pub fn into_events<Event>(
                self,
            ) -> ::std::result::Result<
                ::std::vec::Vec<$crate::reactor::ResolvedEvent<Event>>,
                $crate::reactor::macros::__private::vmi_core::VmiError,
            >
            where
                Event: $crate::reactor::ReactorEvent<Module = $name>,
            {
                $crate::reactor::macros::__private::resolve_events::<Event, __Os>(
                    self.__inner.as_slice(),
                )
            }
        }
    };
}
