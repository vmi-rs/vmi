mod define_events;
mod define_modules;
mod split_attrs;

#[doc(hidden)]
pub mod __private {
    pub mod isr_cache {
        pub use isr_cache::*;
    }

    pub mod vmi_arch_amd64 {
        pub use vmi_arch_amd64::*;
    }

    pub mod vmi_core {
        pub use vmi_core::*;
    }

    pub mod vmi_os_windows {
        pub use vmi_os_windows::*;
    }

    use isr_cache::{Entry as IsrEntry, IsrCache};
    use vmi_core::{Hex, VmiError, VmiOs, VmiSession, driver::VmiFullDriver, os::AnyProcess};
    use vmi_os_windows::{ArchAdapter, WindowsOs};

    use super::super::{
        EventMetadata, ModuleMode, ModuleProcessFilter, ReactorEvent, ReactorModule, ResolvedEvent,
        ResolvedModule,
    };

    type CacheSlots = [Option<IsrEntry>];
    type ModuleSlots<'a> = [Option<ResolvedModule<'a>>];

    /// Resolves unresolved module slots in a generated resolver table.
    ///
    /// Existing slots are left unchanged, which lets callers pre-populate
    /// entries with `with_kernel`, `with_module`, or `with_module_in_process`.
    /// Empty slots are resolved from [`Module::METADATA`]: kernel modules use
    /// the kernel resolver, and user modules use the configured process filter.
    ///
    /// Resolved [`CodeView`] signatures are loaded through the ISR cache,
    /// and the resulting profile references are stored in the module table.
    /// Optional modules that cannot be found are skipped. Non-optional missing
    /// modules cause an error.
    ///
    /// [`Module::METADATA`]: ReactorModule::METADATA
    /// [`CodeView`]: isr_cache::CodeView
    pub fn resolve_modules<'a, Driver, Module>(
        session: &VmiSession<WindowsOs<Driver>>,
        isr: &IsrCache,
        cache: &'a mut CacheSlots,
        modules: &mut ModuleSlots<'a>,
    ) -> Result<(), VmiError>
    where
        Driver: VmiFullDriver,
        Driver::Architecture: ArchAdapter<Driver> + crate::resolver::ArchAdapter<Driver>,
        Module: ReactorModule<WindowsOs<Driver>>,
    {
        debug_assert_eq!(
            Module::METADATA.len(),
            cache.len(),
            "length of entries and module metadata must match"
        );

        debug_assert_eq!(
            cache.len(),
            modules.len(),
            "length of entries and table must match"
        );

        let paused = session.pause_guard()?;

        let vmi = paused.state();

        for (meta, (table_slot, cache_slot)) in Module::METADATA
            .iter()
            .zip(modules.iter_mut().zip(cache.iter_mut()))
        {
            if table_slot.is_some() {
                continue;
            }

            let resolved = match &meta.mode {
                ModuleMode::Kernel => crate::resolver::resolve_kernel_module(&vmi, isr, meta.name)?,
                ModuleMode::User { process } => match process {
                    Some(ModuleProcessFilter::Name(name)) => {
                        crate::resolver::resolve_user_module(&vmi, isr, meta.name, *name)?
                    }
                    Some(ModuleProcessFilter::Predicate(predicate)) => {
                        crate::resolver::resolve_user_module(&vmi, isr, meta.name, *predicate)?
                    }
                    None => crate::resolver::resolve_user_module(&vmi, isr, meta.name, AnyProcess)?,
                },
            };

            match resolved {
                Some(resolved) => {
                    let entry = isr.entry_from_codeview(resolved.debug_signature)?;
                    let profile = cache_slot.insert(entry).profile()?;
                    *table_slot = Some(ResolvedModule {
                        process: resolved.process,
                        base_address: resolved.image_base,
                        profile: profile.into(),
                    });
                }
                None if meta.optional => {
                    tracing::debug!("profile not found (optional)");
                    continue;
                }
                None => {
                    tracing::warn!("profile not found");
                    return Err(VmiError::Other("profile not found"));
                }
            }
        }

        Ok(())
    }

    /// Resolves one event metadata entry against a resolved module table.
    ///
    /// The event's module tag selects either the kernel slot or the slot
    /// returned by [`ReactorModule::slot`]. The primary symbol name is tried
    /// first, followed by aliases in declaration order. A match returns a
    /// [`ResolvedEvent`] whose address is the module base plus the symbol
    /// offset.
    ///
    /// If the module or symbol is absent and either the event or its owning
    /// module is optional, `Ok(None)` is returned. Otherwise the missing
    /// module/profile or symbol causes an error.
    #[tracing::instrument(
        skip_all,
        fields(
            module = %meta.module
                          .map(|module| format!("{module:?}"))
                          .unwrap_or_else(|| String::from("kernel")),
            name = %meta.name
        )
    )]
    pub fn resolve_event<Event, Os>(
        modules: &ModuleSlots,
        meta: &EventMetadata<Event>,
    ) -> Result<Option<ResolvedEvent<Event>>, VmiError>
    where
        Event: ReactorEvent,
        Event::Module: ReactorModule<Os>,
        Os: VmiOs + 'static,
    {
        let slot = meta
            .module
            .map(<Event::Module as ReactorModule<Os>>::slot)
            .unwrap_or(<Event::Module as ReactorModule<Os>>::KERNEL_SLOT);

        let module = match &modules[slot] {
            Some(module) => module,
            None if meta.optional => {
                tracing::debug!("profile not found (event optional)");
                return Ok(None);
            }
            None if <Event::Module as ReactorModule<Os>>::METADATA[slot].optional => {
                tracing::debug!("profile not found (module optional)");
                return Ok(None);
            }
            None => {
                tracing::warn!("profile not found");
                return Err(VmiError::Other("profile not found"));
            }
        };

        if let Some(offset) = module.profile.find_symbol(meta.name) {
            tracing::debug!(offset = %Hex(offset), "symbol found");
            return Ok(Some(ResolvedEvent {
                process: module.process,
                address: module.base_address + offset,
                event: meta.event,
            }));
        }

        match meta.alias.iter().find_map(|&alias| {
            module
                .profile
                .find_symbol(alias)
                .map(|offset| (alias, offset))
        }) {
            Some((alias, offset)) => {
                tracing::debug!(offset = %Hex(offset), alias, "symbol found");
                Ok(Some(ResolvedEvent {
                    process: module.process,
                    address: module.base_address + offset,
                    event: meta.event,
                }))
            }
            None if meta.optional => {
                tracing::debug!("symbol not found (event optional)");
                Ok(None)
            }
            None if <Event::Module as ReactorModule<Os>>::METADATA[slot].optional => {
                tracing::debug!("symbol not found (module optional)");
                Ok(None)
            }
            None => {
                tracing::warn!("symbol not found");
                Err(VmiError::Other("symbol not found"))
            }
        }
    }

    /// Resolves all events declared by an event enum.
    ///
    /// Events are processed in metadata order. Entries that resolve to `Some`
    /// are collected, optional missing entries are omitted, and the first
    /// non-optional resolution error is returned.
    pub fn resolve_events<Event, Os>(
        modules: &ModuleSlots,
    ) -> Result<Vec<ResolvedEvent<Event>>, VmiError>
    where
        Event: ReactorEvent,
        Event::Module: ReactorModule<Os>,
        Os: VmiOs + 'static,
    {
        let mut events = Vec::new();
        for meta in Event::METADATA {
            if let Some(resolved) = resolve_event::<Event, Os>(modules, meta)? {
                events.push(resolved);
            }
        }

        Ok(events)
    }
}

// The functions and macro expansions in this module exist solely so the
// compiler exercises every shape of `define_modules!` / `define_events!`.
#[cfg(test)]
mod tests {
    use vmi_core::{VmiError, VmiOs, driver::VmiRead};
    use vmi_os_windows::{ArchAdapter, WindowsOs, WindowsProcess};

    use super::super::{define_events, define_modules};

    /// Os-generic predicate, callable from the blanket impl form
    /// (`define_modules!` without `#[os(...)]`).
    fn match_by_name<Os>(_process: &Os::Process<'_>) -> Result<bool, VmiError>
    where
        Os: VmiOs,
    {
        Ok(true)
    }

    /// Windows-specific predicate, callable from the anchored impl form
    /// (`#[os(<Driver: VmiRead> WindowsOs<Driver> where ...)]`).
    fn match_windows_process<Driver>(_process: &WindowsProcess<Driver>) -> Result<bool, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        Ok(true)
    }

    #[test]
    fn test_macro() {
        define_modules! {
            /// Rustdoc before attribute.
            #[allow(dead_code)] // Allow attributes. Can be before or after Rustdoc.
            pub enum Module {
                /// Default kernel mode (no `mode(...)`).
                #[module(name = "module1")]
                Module1,

                /// Explicit kernel mode.
                #[module(name = "module2", mode(kernel))]
                /// Rustdoc after attribute.
                Module2,

                /// User mode, no process filter.
                #[module(name = "module3", mode(user), optional)]
                Module3,

                /// User mode, process filter by literal name.
                #[module(optional, name = "module4", mode(user, process = "lsass.exe"))]
                Module4,

                /// User mode, process filter by bare-ident predicate.
                #[module(name = "module5", mode(user, process = match_by_name))]
                Module5,

                /// User mode, process filter by fully-qualified predicate.
                #[module(name = "module6", mode(user, process = self::match_by_name))]
                Module6,
            }

            // #[resolver] ... is required. It tells the macro to generate a resolver struct.
            // Rustdoc/derives/other attributes are forbidden.
            #[resolver]
            pub struct ModuleResolver;

            // #[cache] ... is optional. If provided, the macro will generate a cache struct.
            // Rustdoc/derives/other attributes are forbidden.
            #[cache]
            pub struct SymbolCache;

            // The order of #[resolver] and #[cache] is not fixed. #[cache] can be placed before #[resolver].
        }

        define_events! {
            #[allow(dead_code)] // Allow attributes. Can be before or after Rustdoc.
            /// Rustdoc
            pub enum Event in Module {
                // BEGIN KERNEL EVENTS

                NonOptionalKernelEvent1,

                /// Rustdoc.
                NonOptionalKernelEvent2,

                /// Rustdoc before attribute.
                #[event(optional)]
                OptionalKernelEvent1,

                #[event(optional)]
                /// Rustdoc before attribute.
                OptionalKernelEvent2,

                #[event(optional)]
                OptionalKernelEvent3,

                // END KERNEL EVENTS

                Module1 {
                    /// Rustdoc.
                    Module1Event1,

                    Module1Event2,
                },

                Module2 {
                    /// Rustdoc before attribute.
                    #[event(optional)]
                    Module2Event1,

                    #[event(optional)]
                    /// Rustdoc after attribute.
                    Module2Event2,

                    Module2Event3,
                },

                Module3 {
                    /// Rustdoc before attribute.
                    #[event(
                        name = "AnotherModule3Event1",
                        alias = "AnotherModule3Event1_Alias1" // no trailing comma
                    )]
                    Module3Event1,

                    #[event(
                        name = "AnotherModule3Event2",
                        alias = "AnotherModule3Event2_Alias1",
                    )]
                    /// Rustdoc after attribute.
                    Module3Event2,

                    #[event(
                        name = "AnotherModule3Event3",
                        alias = ["AnotherModule3Event3_Alias1", "AnotherModule3Event3_Alias2"],
                        optional,
                    )]
                    Module3Event3 // trailing comma optional
                },

                Module4 {
                    /// Rustdoc before attribute. Various attribute order.
                    #[event(
                        optional,
                        name = "AnotherModule4Event1",
                        alias = "AnotherModule4Event1_Alias1"
                    )]
                    Module4Event1,

                    #[event(
                        alias = "AnotherModule4Event2_Alias1",
                        name = "AnotherModule4Event2",
                        optional,
                    )]
                    /// Rustdoc after attribute. Various attribute order.
                    Module4Event2,
                }, // trailing comma optional
            }
        }
    }

    /// Anchored form with generic param and where clause. Exercises the
    /// most common shape: one OS family bound to a `Driver` generic, complex
    /// bounds in the where clause, and a Driver-typed predicate.
    #[test]
    fn test_anchored_with_generic_where() {
        define_modules! {
            #[os(
                <Driver: VmiRead> WindowsOs<Driver>
                where Driver::Architecture: ArchAdapter<Driver>
            )]
            pub enum AnchoredWhereModule {
                #[module(name = "kmod", mode(kernel))]
                Kmod,

                #[module(name = "umod", mode(user, process = match_windows_process))]
                Umod,
            }

            #[resolver]
            pub struct AnchoredWhereResolver;

            #[cache]
            pub struct AnchoredWhereCache;
        }
    }

    /// Anchored form with a generic carrying no inline bound (everything in
    /// the where clause).
    #[test]
    fn test_anchored_bare_generic_all_in_where() {
        define_modules! {
            #[os(
                <Driver> WindowsOs<Driver>
                where Driver: VmiRead, Driver::Architecture: ArchAdapter<Driver>
            )]
            pub enum AnchoredBareModule {
                #[module(name = "a", mode(user, process = match_windows_process))]
                A,
            }

            #[resolver]
            pub struct AnchoredBareResolver;
        }
    }

    /// Bare enum: no `#[resolver]`, no `#[cache]`. Only the enum and its
    /// blanket `ReactorModule` impl are emitted.
    #[test]
    fn test_no_resolver_no_cache() {
        define_modules! {
            #[allow(dead_code)]
            pub enum BareModule {
                #[module(name = "a")]
                A,

                #[module(name = "b", mode(user))]
                B,
            }
        }
    }

    /// `#[resolver]` present, `#[cache]` absent. Resolver gets `with_kernel`,
    /// `with_module`, `into_events` but no `resolve` method.
    #[test]
    fn test_resolver_only() {
        define_modules! {
            pub enum ResolverOnlyModule {
                #[module(name = "a")]
                A,
            }

            #[resolver]
            pub struct ResolverOnlyResolver;
        }
    }

    /// `#[cache]` declared before `#[resolver]`. The trailing-marker arms in
    /// `@finalize` accept either order.
    #[test]
    fn test_cache_before_resolver() {
        define_modules! {
            pub enum SwappedOrderModule {
                #[module(name = "a")]
                A,
            }

            #[cache]
            pub struct SwappedOrderCache;

            #[resolver]
            pub struct SwappedOrderResolver;
        }
    }

    /// `#[os(...)]` position-independence: before rustdoc, after rustdoc,
    /// between other attributes. The walker in `@walk_enum_attrs` peels it
    /// out wherever it appears.
    #[test]
    fn test_os_attr_positions() {
        define_modules! {
            #[os(<Driver: VmiRead> WindowsOs<Driver> where Driver::Architecture: ArchAdapter<Driver>)]
            /// Os attribute before rustdoc.
            #[allow(dead_code)]
            pub enum OsPositionA {
                #[module(name = "a")]
                A,
            }

            #[resolver]
            pub struct OsPositionAResolver;
        }

        define_modules! {
            /// Os attribute after rustdoc.
            #[os(<Driver: VmiRead> WindowsOs<Driver> where Driver::Architecture: ArchAdapter<Driver>)]
            #[allow(dead_code)]
            pub enum OsPositionB {
                #[module(name = "a")]
                A,
            }

            #[resolver]
            pub struct OsPositionBResolver;
        }

        define_modules! {
            /// Os attribute between rustdoc and `#[allow(...)]`.
            #[allow(dead_code)]
            #[os(<Driver: VmiRead> WindowsOs<Driver> where Driver::Architecture: ArchAdapter<Driver>)]
            pub enum OsPositionC {
                #[module(name = "a")]
                A,
            }

            #[resolver]
            pub struct OsPositionCResolver;
        }
    }

    /// `#[module(...)]` argument ordering. `name = "..."`, `mode(...)`, and
    /// `optional` may appear in any order.
    #[test]
    fn test_module_arg_order() {
        define_modules! {
            pub enum ArgOrderModule {
                #[module(name = "a")]
                A,

                #[module(optional, name = "b")]
                B,

                #[module(name = "c", optional)]
                C,

                #[module(mode(user), name = "d")]
                D,

                #[module(optional, mode(kernel), name = "e")]
                E,

                #[module(name = "f", optional, mode(user, process = match_by_name))]
                F,

                #[module(mode(user, process = "lsass.exe"), optional, name = "g")]
                G,
            }

            #[resolver]
            pub struct ArgOrderResolver;
        }
    }

    /// Every `mode(...)` shape in one enum: omitted (default kernel),
    /// `kernel`, `user`, `user, process = "literal"`, `user, process = ident`,
    /// `user, process = path::with::segments`.
    #[test]
    fn test_mode_shapes() {
        define_modules! {
            pub enum ModeShapesModule {
                /// Omitted - defaults to kernel.
                #[module(name = "default")]
                Default,

                /// Explicit kernel.
                #[module(name = "kernel", mode(kernel))]
                Kernel,

                /// User with no process filter.
                #[module(name = "any-user", mode(user))]
                AnyUser,

                /// User with literal-name filter.
                #[module(name = "by-name", mode(user, process = "lsass.exe"))]
                ByName,

                /// User with bare-ident predicate.
                #[module(name = "by-ident", mode(user, process = match_by_name))]
                ByIdent,

                /// User with fully-qualified path predicate.
                #[module(name = "by-path", mode(user, process = self::match_by_name))]
                ByPath,
            }

            #[resolver]
            pub struct ModeShapesResolver;
        }
    }

    /// Events with mixed shapes: kernel events with and without rustdoc,
    /// module groups with the alias array form, optional events, and
    /// implicit names (variant ident becomes the symbol name).
    #[test]
    fn test_event_shapes() {
        define_modules! {
            pub enum EventShapesModule {
                #[module(name = "m1")]
                M1,

                #[module(name = "m2")]
                M2,
            }

            #[resolver]
            pub struct EventShapesResolver;
        }

        define_events! {
            #[allow(dead_code)]
            pub enum EventShapesEvent in EventShapesModule {
                /// Kernel event, implicit name.
                KernelImplicit,

                #[event(name = "RenamedKernel", optional)]
                KernelRenamedOptional,

                M1 {
                    /// Implicit name.
                    M1Implicit,

                    #[event(optional)]
                    M1Optional,
                },

                M2 {
                    #[event(name = "M2Renamed")]
                    M2Renamed,

                    #[event(
                        name = "M2Aliased",
                        alias = ["AliasA", "AliasB", "AliasC"],
                        optional,
                    )]
                    M2Aliased,
                },
            }
        }
    }
}
