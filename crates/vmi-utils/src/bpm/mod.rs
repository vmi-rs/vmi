//! Breakpoint management.
//!
//! Provides breakpoint management capabilities, including handling of page-in
//! and page-out events, and support for both active and pending breakpoints.
//! The [`BreakpointManager`] is designed to work in conjunction with the
//! [`PageTableMonitor`].
//!
//! When a page-out event occurs, active breakpoints on that page are
//! automatically removed and preserved as pending entries. When a page-in
//! event occurs, pending breakpoints are restored.
//!
//! The breakpoint manager also supports setting breakpoints for virtual
//! addresses that aren't currently mapped to physical memory - these will be
//! automatically activated once the address translation becomes available.
//!
//! # Controllers
//!
//! The breakpoint manager works with controllers that implement the
//! [`TapController`] trait. Two primary implementations are provided:
//!
//! ## [`BreakpointController`]
//!
#![doc = include_str!("./controller/breakpoint.md")]
//!
//! ## [`MemoryController`]
//!
#![doc = include_str!("./controller/memory.md")]
//!
//! [`PageTableMonitor`]: crate::ptm::PageTableMonitor

mod breakpoint;
use self::breakpoint::{ActiveBreakpoints, PendingBreakpoints};
pub use self::breakpoint::{
    Breakpoint, BreakpointBuilder, BreakpointBuilderWithKey, BreakpointBuilderWithKeyTag,
    BreakpointBuilderWithTag, KeyType, TagType,
};

mod controller;
use std::collections::{HashMap, HashSet, hash_map::Entry};

use vmi_core::{
    AddressContext, Architecture as _, Gfn, Pa, Registers as _, Va, View, VmiCore, VmiDriver,
    VmiError, VmiEvent, driver::VmiRead,
};

pub use self::controller::{BreakpointController, MemoryController, TapController};
use crate::ptm::{PageEntryUpdate, PageTableMonitorEvent};

/// Breakpoint manager.
pub struct BreakpointManager<Controller, Key = (), Tag = &'static str>
where
    Controller: TapController,
    Controller::Driver: VmiRead,
    Key: KeyType,
    Tag: TagType,
{
    /// Stores active breakpoints for addresses currently in physical memory.
    ///
    /// * Key: (View, GFN)
    /// * Value: Map of breakpoints, where each breakpoint is identified by
    ///   (Key, AddressContext) and associated with a set of Breakpoints
    ///
    /// This map is synchronized with `active_global_breakpoints`, `active_locations`,
    /// and `active_gfns_by_view`.
    ///
    /// Breakpoints move between `active_breakpoints` and `pending_breakpoints`
    /// based on page-in and page-out events.
    active_breakpoints: HashMap<(View, Gfn), ActiveBreakpoints<Key, Tag>>,

    /// Stores global breakpoints indexed by their virtual addresses.
    ///
    /// * Key: (View, Virtual Address)
    /// * Value: Global Breakpoint information, including the root address (e.g.,
    ///   `CR3` on x86 architectures) for which the global breakpoint was
    ///   initially registered.
    ///
    /// Note: Each VA is associated with a single root address. If support for
    /// multiple roots per VA is needed, this structure may need to be adjusted.
    active_global_breakpoints: HashMap<(View, Va), GlobalBreakpoint>,

    /// Maps breakpoint identifiers to their locations across views and GFNs.
    ///
    /// * Key: (Key, AddressContext)
    /// * Value: Set of (View, GFN) pairs where this breakpoint is active
    ///
    /// This map is kept in sync with `active_breakpoints` to allow efficient
    /// lookup of breakpoint locations.
    active_locations: HashMap<(Key, AddressContext), HashSet<(View, Gfn)>>,

    /// Tracks which GFNs are monitored in each view.
    ///
    /// * Key: View
    /// * Value: Set of GFNs monitored in this view
    ///
    /// This map is kept in sync with `active_breakpoints` and `monitored_gfns_by_view`.
    active_gfns_by_view: HashMap<View, HashSet<Gfn>>,

    /// Stores pending breakpoints for addresses not currently in physical memory.
    ///
    /// * Key: AddressContext (Virtual Address, Root)
    /// * Value: Set of pending breakpoints for that address
    ///
    /// Breakpoints move between `active_breakpoints` and `pending_breakpoints`
    /// based on page-in and page-out events.
    pending_breakpoints: HashMap<(View, AddressContext), PendingBreakpoints<Key, Tag>>,

    /// Maps pending breakpoints to their views.
    /// This map is used to quickly remove pending breakpoints when a view is
    /// removed.
    ///
    /// * Key: View
    /// * Value: Set of pending breakpoints for that view
    ///
    /// This map is kept in sync with `pending_breakpoints`.
    pending_ctx_by_view: HashMap<View, HashSet<AddressContext>>,

    /// Controller used to insert and remove breakpoints.
    controller: Controller,
}

#[derive(Debug)]
struct GlobalBreakpoint {
    root: Pa,
    gfns: HashMap<Gfn, u32>,
}

/*
impl<Controller, Key, Tag> Drop for Tap<Controller, Key, Tag>
where
    Controller: TapController,
    Controller::Driver: VmiDriver,
    Key: KeyType,
    Tag: TagType,
{
    fn drop(&mut self) {
        println!("dropping breakpoint manager");
        println!("active_breakpoints: {:#?}", self.active_breakpoints);
        println!(
            "active_global_breakpoints: {:#?}",
            self.active_global_breakpoints
        );
        println!("active_locations: {:#?}", self.active_locations);
        println!("active_gfns_by_view: {:#?}", self.active_gfns_by_view);
        println!("pending_breakpoints: {:#?}", self.pending_breakpoints);
        println!("pending_ctx_by_view: {:#?}", self.pending_ctx_by_view);
    }
}
*/

impl<Interface, Key, Tag> BreakpointManager<Interface, Key, Tag>
where
    Interface: TapController,
    Interface::Driver: VmiRead,
    Key: KeyType,
    Tag: TagType,
{
    #[expect(clippy::new_without_default)]
    /// Creates a new breakpoint manager.
    pub fn new() -> Self {
        Self {
            active_breakpoints: HashMap::new(),
            active_global_breakpoints: HashMap::new(),
            active_locations: HashMap::new(),
            active_gfns_by_view: HashMap::new(),
            pending_breakpoints: HashMap::new(),
            pending_ctx_by_view: HashMap::new(),
            controller: Interface::new(),
        }
    }

    /// Inserts a breakpoint.
    ///
    /// The breakpoint is registered as pending when the translation for the
    /// virtual address is not present. When the translation is present, the
    /// breakpoint is immediately inserted.
    ///
    /// Consider using [`insert_with_hint`] when the physical address is known.
    ///
    /// Returns `true` if the breakpoint was newly inserted, `false` if it was
    /// already present.
    ///
    /// [`insert_with_hint`]: Self::insert_with_hint
    pub fn insert(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        breakpoint: impl Into<Breakpoint<Key, Tag>>,
    ) -> Result<bool, VmiError> {
        let breakpoint = breakpoint.into();

        //
        // Check if the translation for the virtual address is present.
        // If it is, insert the breakpoint.
        // If it is not, register the breakpoint as pending.
        //

        match vmi.translate_address(breakpoint.ctx) {
            Ok(pa) => self.insert_with_hint(vmi, breakpoint, Some(pa)),
            Err(VmiError::Translation(_)) => self.insert_with_hint(vmi, breakpoint, None),
            Err(err) => Err(err),
        }
    }

    /// Inserts a breakpoint with a hint for the physical address.
    /// If the physical address is `None`, the breakpoint is registered as
    /// pending.
    ///
    /// This function is useful when the physical address is known in advance,
    /// for example, when the breakpoint is inserted in response to a page
    /// table update.
    ///
    /// The user is responsible for ensuring that the physical address is
    /// correct.
    ///
    /// Returns `true` if the breakpoint was newly inserted, `false` if it was
    /// already present.
    pub fn insert_with_hint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        breakpoint: impl Into<Breakpoint<Key, Tag>>,
        pa: Option<Pa>,
    ) -> Result<bool, VmiError> {
        let breakpoint = breakpoint.into();

        //
        // Check if the physical address is provided.
        // If it is, insert the breakpoint.
        // If it is not, register the breakpoint as pending.
        //

        let pa = match pa {
            Some(pa) => pa,
            None => return Ok(self.insert_pending_breakpoint(breakpoint)),
        };

        self.insert_active_breakpoint(vmi, breakpoint, pa)
    }

    /// Removes a breakpoint.
    ///
    /// When a translation for the virtual address is not present, the breakpoint
    /// is removed from the pending breakpoints. When the translation is present,
    /// the breakpoint is removed from the active breakpoints.
    ///
    /// Returns `true` if the breakpoint was removed, `false` if it was not
    /// found.
    pub fn remove(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        breakpoint: impl Into<Breakpoint<Key, Tag>>,
    ) -> Result<bool, VmiError> {
        let breakpoint = breakpoint.into();

        match vmi.translate_address(breakpoint.ctx) {
            Ok(pa) => self.remove_with_hint(vmi, breakpoint, Some(pa)),
            Err(VmiError::Translation(_)) => self.remove_with_hint(vmi, breakpoint, None),
            Err(err) => Err(err),
        }
    }

    /// Removes a breakpoint with a hint for the physical address.
    ///
    /// If the physical address is `None`, the breakpoint is removed from
    /// the pending breakpoints. If the physical address is provided, the
    /// breakpoint is removed from the active breakpoints.
    ///
    /// Returns `true` if the breakpoint was removed, `false` if it was not
    /// found.
    pub fn remove_with_hint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        breakpoint: impl Into<Breakpoint<Key, Tag>>,
        pa: Option<Pa>,
    ) -> Result<bool, VmiError> {
        let breakpoint = breakpoint.into();

        if self.remove_pending_breakpoint(breakpoint) {
            return Ok(true);
        }

        let pa = match pa {
            Some(pa) => pa,
            None => return Ok(false),
        };

        let breakpoint_was_removed =
            self.remove_active_breakpoint_definition(vmi, breakpoint, pa)?;
        Ok(breakpoint_was_removed.is_some())
    }

    /// Removes a breakpoint by event that caused the breakpoint.
    ///
    /// Returns either:
    /// - `Some(true)` if the breakpoint was removed and it was the last
    ///   breakpoint for the `(view, GFN)` pair.
    /// - `Some(false)` if the breakpoint was removed but there are still
    ///   other breakpoints for the `(view, GFN)` pair.
    /// - `None` if the breakpoint was not found.
    pub fn remove_by_event(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        event: &VmiEvent<<Interface::Driver as VmiDriver>::Architecture>,
        key: Key,
    ) -> Result<Option<bool>, VmiError> {
        let (ctx, pa, view) = match self.address_for_event(event) {
            Some((ctx, pa, view)) => (ctx, pa, view),
            None => return Ok(None),
        };

        let result = self.remove_active_breakpoint(vmi, ctx, pa, key, view)?;

        //
        // Remove active breakpoints for all views.
        //

        let views = match self.active_locations.get(&(key, ctx)) {
            Some(views) => views.clone(),
            None => return Ok(result),
        };

        for (view, gfn) in views {
            let pa = self.pa_from_gfn_and_va(gfn, ctx.va);

            //
            // If breakpoints are being removed by event, there should be no
            // pending breakpoints for this address (because the address caused
            // this event, it should be in physical memory).
            //
            //self.unregister_pending_breakpoints(ctx, view);

            self.remove_active_breakpoint(vmi, ctx, pa, key, view)?;
        }

        Ok(result)
    }

    /// Removes all breakpoints for a given view.
    ///
    /// Returns `true` if any breakpoints were removed, `false` otherwise.
    pub fn remove_by_view(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        view: View,
    ) -> Result<bool, VmiError> {
        let mut removed = false;

        if let Some(pending_ctxs) = self.pending_ctx_by_view.get(&view).cloned() {
            for ctx in pending_ctxs {
                removed |= self
                    .remove_pending_breakpoints_by_address(ctx, view)
                    .is_some();
            }
        }

        if let Some(gfns) = self.active_gfns_by_view.get(&view).cloned() {
            debug_assert!(!gfns.is_empty(), "active_gfns_by_view is empty");

            for gfn in gfns {
                removed |= self
                    .remove_active_breakpoints_by_location(vmi, gfn, view)?
                    .is_some();
            }
        }

        Ok(removed)
    }

    /// Returns an iterator over the breakpoints for the given event.
    pub fn get_by_event(
        &mut self,
        event: &VmiEvent<<Interface::Driver as VmiDriver>::Architecture>,
        key: Key,
    ) -> Option<impl ExactSizeIterator<Item = Breakpoint<Key, Tag>> + use<'_, Interface, Key, Tag>>
    {
        let (ctx, pa, view) = self.address_for_event(event)?;
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        let breakpoints_by_ctx = self.active_breakpoints.get(&(view, gfn))?;
        let breakpoints = breakpoints_by_ctx.get(&(key, ctx))?;

        Some(breakpoints.iter().copied())
    }

    /// Checks if the given event was caused by a breakpoint.
    pub fn contains_by_event(
        &self,
        event: &VmiEvent<<Interface::Driver as VmiDriver>::Architecture>,
        key: Key,
    ) -> bool {
        let (ctx, pa, view) = match self.address_for_event(event) {
            Some((ctx, pa, view)) => (ctx, pa, view),
            None => return false,
        };

        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);
        let breakpoints = match self.active_breakpoints.get(&(view, gfn)) {
            Some(breakpoints) => breakpoints,
            None => return false,
        };

        breakpoints.contains_key(&(key, ctx))
    }

    /// Checks if a breakpoint is active for the given address.
    pub fn contains_by_address(&self, ctx: impl Into<AddressContext>, key: Key) -> bool {
        let ctx = ctx.into();

        self.active_locations.contains_key(&(key, ctx))
    }

    /// Clears all breakpoints.
    ///
    /// This function removes all active and pending breakpoints.
    pub fn clear(&mut self, vmi: &VmiCore<Interface::Driver>) -> Result<(), VmiError> {
        let locations = self.active_breakpoints.keys().copied().collect::<Vec<_>>();

        for (view, gfn) in locations {
            self.remove_active_breakpoints_by_location(vmi, gfn, view)?;
        }

        self.pending_breakpoints.clear();
        self.pending_ctx_by_view.clear();

        debug_assert!(self.active_breakpoints.is_empty());
        debug_assert!(self.active_global_breakpoints.is_empty());
        debug_assert!(self.active_locations.is_empty());
        debug_assert!(self.active_gfns_by_view.is_empty());
        debug_assert!(self.pending_breakpoints.is_empty());
        debug_assert!(self.pending_ctx_by_view.is_empty());

        Ok(())
    }

    /// Handles a page table monitor event.
    ///
    /// This function should be called when a page table monitor event is
    /// received. It will update the internal state of the breakpoint
    /// manager accordingly.
    ///
    /// On page-in events, the function will check if there are any pending
    /// breakpoints that can be made active.
    ///
    /// On page-out events, the function will check if there are any active
    /// breakpoints that need to made pending.
    ///
    /// Returns `true` if any breakpoints were updated, `false` otherwise.
    pub fn handle_ptm_event(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        event: &PageTableMonitorEvent,
    ) -> Result<bool, VmiError> {
        match event {
            PageTableMonitorEvent::PageIn(update) => self.handle_page_in(vmi, update),
            PageTableMonitorEvent::PageOut(update) => self.handle_page_out(vmi, update),
        }
    }

    /// Handles a batch of page table monitor events.
    ///
    /// Convenience method that processes multiple [`PageTableMonitorEvent`]s
    /// by delegating each to [`handle_ptm_event`](Self::handle_ptm_event).
    ///
    /// Returns `true` if any breakpoints were updated, `false` otherwise.
    /// Short-circuits on the first error.
    pub fn handle_ptm_events(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        events: impl IntoIterator<Item = PageTableMonitorEvent>,
    ) -> Result<bool, VmiError> {
        let mut updated = false;

        for event in events {
            updated |= self.handle_ptm_event(vmi, &event)?;
        }

        Ok(updated)
    }

    /// Handles a page-in event.
    ///
    /// This function should be called when a page-in event is received.
    /// It will check if there are any pending breakpoints that can be made
    /// active.
    ///
    /// Returns `true` if any breakpoints were updated, `false` otherwise.
    fn handle_page_in(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        update: &PageEntryUpdate,
    ) -> Result<bool, VmiError> {
        tracing::trace!(?update, "page-in");

        let ctx = update.ctx;
        let view = update.view;
        let pa = update.pa;

        let breakpoints = match self.remove_pending_breakpoints_by_address(ctx, view) {
            Some(breakpoints) => breakpoints,
            None => return Ok(false),
        };
        let mut activated = Vec::with_capacity(breakpoints.len());

        for breakpoint in breakpoints {
            if let Err(err) = self.insert_active_breakpoint(vmi, breakpoint, pa) {
                self.insert_pending_breakpoint(breakpoint);

                for activated_breakpoint in activated {
                    match self.remove_active_breakpoint_definition(vmi, activated_breakpoint, pa) {
                        Ok(Some(_)) => {
                            self.insert_pending_breakpoint(activated_breakpoint);
                        }
                        Ok(None) => {
                            tracing::error!(
                                ?activated_breakpoint,
                                "activated breakpoint disappeared during page-in rollback"
                            );
                        }
                        Err(rollback_err) => {
                            tracing::error!(
                                %rollback_err,
                                ?activated_breakpoint,
                                "failed to roll back breakpoint after page-in failure"
                            );
                        }
                    }
                }

                return Err(err);
            }

            activated.push(breakpoint);
        }

        Ok(true)
    }

    /// Handles a page-out event.
    ///
    /// This function should be called when a page-out event is received.
    /// It will check if there are any active breakpoints that need to be made
    /// pending.
    ///
    /// Returns `true` if any breakpoints were updated, `false` otherwise.
    fn handle_page_out(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        update: &PageEntryUpdate,
    ) -> Result<bool, VmiError> {
        tracing::trace!(?update, "page-out");

        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(update.pa);
        let view = update.view;

        let breakpoints_by_ctx = match self.remove_active_breakpoints_by_location(vmi, gfn, view)? {
            Some(breakpoints_by_ctx) => breakpoints_by_ctx,
            None => return Ok(false),
        };

        for breakpoint in breakpoints_by_ctx.into_values().flatten() {
            self.insert_pending_breakpoint(breakpoint);
        }

        Ok(true)
    }

    /// Inserts an active breakpoint.
    ///
    /// This function is used to register a breakpoint that can be immediately
    /// inserted. The breakpoint is inserted into the active breakpoints map
    /// and the monitored views map.
    ///
    /// Returns `true` if the breakpoint was newly inserted, `false` if it was
    /// already present.
    fn insert_active_breakpoint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        mut breakpoint: Breakpoint<Key, Tag>,
        pa: Pa,
    ) -> Result<bool, VmiError> {
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        if breakpoint.global {
            self.normalize_global_context(breakpoint.view, &mut breakpoint.ctx);
        }

        let Breakpoint {
            ctx,
            view,
            global,
            key,
            tag,
        } = breakpoint;

        if let Some(breakpoints) = self
            .active_breakpoints
            .get_mut(&(view, gfn))
            .and_then(|breakpoints_by_ctx| breakpoints_by_ctx.get_mut(&(key, ctx)))
        {
            let had_global_breakpoint = breakpoints.iter().any(|breakpoint| breakpoint.global);
            let definition_was_inserted = breakpoints.insert(breakpoint);

            if definition_was_inserted && global && !had_global_breakpoint {
                self.register_global_breakpoint(gfn, view, ctx);
            }

            debug_assert!(self.active_locations.contains_key(&(key, ctx)));
            return Ok(false);
        }

        let page_was_inserted = !self.active_breakpoints.contains_key(&(view, gfn));

        self.controller.insert_breakpoint(vmi, pa, view)?;

        if page_was_inserted && let Err(err) = self.controller.monitor(vmi, gfn, view) {
            if let Err(rollback_err) = self.remove_controller_breakpoint(vmi, pa, view) {
                tracing::error!(
                    %rollback_err,
                    %pa,
                    %view,
                    "failed to roll back breakpoint after monitor failure"
                );
            }

            return Err(err);
        }

        self.active_breakpoints
            .entry((view, gfn))
            .or_default()
            .insert((key, ctx), HashSet::from([breakpoint]));

        let location_was_inserted = self
            .active_locations
            .entry((key, ctx))
            .or_default()
            .insert((view, gfn));
        debug_assert!(location_was_inserted);

        if page_was_inserted {
            self.insert_monitored_location(gfn, view);
        }

        if global {
            self.register_global_breakpoint(gfn, view, ctx);
        }

        tracing::debug!(
            active = self.active_breakpoints.len(),
            %gfn, %ctx, %view, %global, ?key, ?tag,
            "active breakpoint inserted"
        );

        Ok(true)
    }

    /// Removes an active breakpoint.
    ///
    /// Returns either:
    /// - `Some(true)` if the breakpoint was removed and it was the last
    ///   breakpoint for the `(view, GFN)` pair.
    /// - `Some(false)` if the breakpoint was removed but there are still
    ///   other breakpoints for the `(view, GFN)` pair.
    /// - `None` if the breakpoint was not found.
    fn remove_active_breakpoint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        ctx: impl Into<AddressContext>,
        pa: Pa,
        key: Key,
        view: View,
    ) -> Result<Option<bool>, VmiError> {
        self.remove_active_breakpoint_internal(vmi, ctx.into(), pa, key, view, None)
    }

    /// Removes one exact breakpoint definition.
    fn remove_active_breakpoint_definition(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        mut breakpoint: Breakpoint<Key, Tag>,
        pa: Pa,
    ) -> Result<Option<bool>, VmiError> {
        if breakpoint.global {
            self.normalize_global_context(breakpoint.view, &mut breakpoint.ctx);
        }

        self.remove_active_breakpoint_internal(
            vmi,
            breakpoint.ctx,
            pa,
            breakpoint.key,
            breakpoint.view,
            Some(breakpoint),
        )
    }

    /// Removes either one definition or every definition for an active key.
    fn remove_active_breakpoint_internal(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        ctx: AddressContext,
        pa: Pa,
        key: Key,
        view: View,
        definition: Option<Breakpoint<Key, Tag>>,
    ) -> Result<Option<bool>, VmiError> {
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);
        let breakpoints_by_ctx = match self.active_breakpoints.get(&(view, gfn)) {
            Some(breakpoints_by_ctx) => breakpoints_by_ctx,
            None => return Ok(None),
        };
        let breakpoints = match breakpoints_by_ctx.get(&(key, ctx)) {
            Some(breakpoints) => breakpoints,
            None => return Ok(None),
        };

        if let Some(definition) = definition {
            if !breakpoints.contains(&definition) {
                return Ok(None);
            }

            if breakpoints.len() > 1 {
                let unregister_global = definition.global
                    && breakpoints
                        .iter()
                        .filter(|breakpoint| breakpoint.global)
                        .count()
                        == 1;

                self.active_breakpoints
                    .get_mut(&(view, gfn))
                    .and_then(|breakpoints_by_ctx| breakpoints_by_ctx.get_mut(&(key, ctx)))
                    .expect("active breakpoint disappeared")
                    .remove(&definition);

                if unregister_global {
                    self.unregister_global_breakpoint(gfn, view, ctx);
                }

                return Ok(Some(false));
            }
        }

        let last_breakpoint_removed = breakpoints_by_ctx.len() == 1;

        self.remove_controller_breakpoint(vmi, pa, view)?;

        if last_breakpoint_removed && let Err(err) = self.unmonitor_controller_page(vmi, gfn, view)
        {
            if let Err(rollback_err) = self.controller.insert_breakpoint(vmi, pa, view) {
                tracing::error!(
                    %rollback_err,
                    %pa,
                    %view,
                    "failed to restore breakpoint after unmonitor failure"
                );
            }

            return Err(err);
        }

        let breakpoints = self
            .active_breakpoints
            .get_mut(&(view, gfn))
            .expect("active breakpoint page disappeared")
            .remove(&(key, ctx))
            .expect("active breakpoint disappeared");

        if breakpoints.iter().any(|breakpoint| breakpoint.global) {
            self.unregister_global_breakpoint(gfn, view, ctx);
        }

        self.remove_active_location(gfn, view, key, ctx);

        if last_breakpoint_removed {
            self.active_breakpoints.remove(&(view, gfn));
            self.remove_monitored_location(gfn, view);
        }

        tracing::debug!(
            %gfn, %ctx, %view, ?key, ?breakpoints,
            "active breakpoint removed"
        );

        Ok(Some(last_breakpoint_removed))
    }

    /// Removes all active breakpoints for a given `(view, GFN)` pair.
    fn remove_active_breakpoints_by_location(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<Option<ActiveBreakpoints<Key, Tag>>, VmiError> {
        let breakpoints = match self.active_breakpoints.get(&(view, gfn)).cloned() {
            Some(breakpoints) => breakpoints,
            None => return Ok(None),
        };
        let mut removed = Vec::with_capacity(breakpoints.len());

        for &(key, ctx) in breakpoints.keys() {
            let pa = self.pa_from_gfn_and_va(gfn, ctx.va);

            if let Err(err) = self.remove_controller_breakpoint(vmi, pa, view) {
                self.restore_controller_breakpoints(vmi, view, &removed);
                return Err(err);
            }

            removed.push((key, ctx, pa));
        }

        if let Err(err) = self.unmonitor_controller_page(vmi, gfn, view) {
            self.restore_controller_breakpoints(vmi, view, &removed);
            return Err(err);
        }

        self.active_breakpoints.remove(&(view, gfn));

        for (&(key, ctx), definitions) in &breakpoints {
            if definitions.iter().any(|breakpoint| breakpoint.global) {
                self.unregister_global_breakpoint(gfn, view, ctx);
            }

            self.remove_active_location(gfn, view, key, ctx);
        }

        self.remove_monitored_location(gfn, view);

        tracing::debug!(
            active = self.active_breakpoints.len(),
            %gfn,
            %view,
            ?breakpoints,
            "active breakpoints removed"
        );

        Ok(Some(breakpoints))
    }

    /// Inserts a pending breakpoint.
    ///
    /// Returns `true` if the breakpoint was newly inserted, `false` if it was
    /// already present.
    fn insert_pending_breakpoint(&mut self, breakpoint: Breakpoint<Key, Tag>) -> bool {
        let Breakpoint {
            ctx,
            view,
            global,
            key,
            tag,
            ..
        } = breakpoint;

        let result = self
            .pending_breakpoints
            .entry((view, ctx))
            .or_default()
            .insert(breakpoint);

        self.pending_ctx_by_view
            .entry(view)
            .or_default()
            .insert(ctx);

        tracing::debug!(
            pending = self.pending_breakpoints.len(),
            %ctx,
            %view,
            %global,
            ?key,
            ?tag,
            "pending breakpoint inserted"
        );

        result
    }

    /// Removes all pending breakpoints for a given `(view, ctx)` pair.
    ///
    /// Returns the pending breakpoints if they were removed, `None` otherwise.
    fn remove_pending_breakpoints_by_address(
        &mut self,
        ctx: AddressContext,
        view: View,
    ) -> Option<PendingBreakpoints<Key, Tag>> {
        let breakpoints = self.pending_breakpoints.remove(&(view, ctx))?;

        match self.pending_ctx_by_view.entry(view) {
            Entry::Occupied(mut entry) => {
                let addresses = entry.get_mut();
                let address_was_removed = addresses.remove(&ctx);
                debug_assert!(
                    address_was_removed,
                    "desynchronized pending_breakpoints and pending_ctx_by_view"
                );

                if addresses.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {
                //
                // `remove_breakpoints_by_view()` removes the entry before
                // calling this function.
                //
            }
        }

        tracing::debug!(
            pending = self.pending_breakpoints.len(),
            %ctx,
            ?breakpoints,
            "pending breakpoints removed"
        );

        Some(breakpoints)
    }
    /// Removes one exact pending breakpoint definition.
    fn remove_pending_breakpoint(&mut self, breakpoint: Breakpoint<Key, Tag>) -> bool {
        let ctx = breakpoint.ctx;
        let view = breakpoint.view;
        let (definition_was_removed, address_is_empty) =
            match self.pending_breakpoints.get_mut(&(view, ctx)) {
                Some(breakpoints) => {
                    let definition_was_removed = breakpoints.remove(&breakpoint);
                    (definition_was_removed, breakpoints.is_empty())
                }
                None => return false,
            };

        if definition_was_removed && address_is_empty {
            self.remove_pending_breakpoints_by_address(ctx, view);
        }

        definition_was_removed
    }

    fn normalize_global_context(&self, view: View, ctx: &mut AddressContext) {
        if let Some(global_breakpoint) = self.active_global_breakpoints.get(&(view, ctx.va)) {
            ctx.root = global_breakpoint.root;
        }
    }

    fn register_global_breakpoint(&mut self, gfn: Gfn, view: View, ctx: AddressContext) {
        match self.active_global_breakpoints.entry((view, ctx.va)) {
            Entry::Occupied(mut entry) => {
                let global_breakpoint = entry.get_mut();
                *global_breakpoint.gfns.entry(gfn).or_default() += 1;
            }
            Entry::Vacant(entry) => {
                entry.insert(GlobalBreakpoint {
                    root: ctx.root,
                    gfns: HashMap::from([(gfn, 1)]),
                });
            }
        }
    }

    fn unregister_global_breakpoint(
        &mut self,
        gfn: Gfn,
        view: View,
        ctx: AddressContext,
    ) -> Option<bool> {
        let mut global_breakpoint = match self.active_global_breakpoints.entry((view, ctx.va)) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };
        let gfns = &mut global_breakpoint.get_mut().gfns;
        let references = gfns.get_mut(&gfn)?;

        if *references > 1 {
            *references -= 1;
            return Some(false);
        }

        gfns.remove(&gfn);

        if !gfns.is_empty() {
            return Some(false);
        }

        global_breakpoint.remove();
        Some(true)
    }

    fn insert_monitored_location(&mut self, gfn: Gfn, view: View) {
        //
        // Verify that the active breakpoint is inserted before monitoring the
        // `(view, GFN)` pair.
        //

        debug_assert!(
            self.active_breakpoints.contains_key(&(view, gfn)),
            "breakpoint must be in active_breakpoints before monitoring"
        );

        let gfn_was_inserted = self
            .active_gfns_by_view
            .entry(view)
            .or_default()
            .insert(gfn);

        //
        // The GFN should not have been monitored before.
        //

        debug_assert!(
            gfn_was_inserted,
            "trying to monitor an already monitored GFN"
        );
    }

    fn remove_monitored_location(&mut self, gfn: Gfn, view: View) {
        //
        // Verify that the active breakpoint is removed before unmonitoring the
        // `(view, GFN)` pair.
        //

        debug_assert!(
            !self.active_breakpoints.contains_key(&(view, gfn)),
            "breakpoint must be removed from active_breakpoints before unmonitoring"
        );

        match self.active_gfns_by_view.entry(view) {
            Entry::Occupied(mut entry) => {
                let gfns = entry.get_mut();
                let gfn_was_present = gfns.remove(&gfn);
                debug_assert!(gfn_was_present, "trying to unmonitor a non-monitored gfn");

                if gfns.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {
                //
                // `remove_breakpoints_by_view()` removes the entry before
                // calling this function.
                //
            }
        }
    }

    /// Removes a location from the active breakpoint index.
    fn remove_active_location(&mut self, gfn: Gfn, view: View, key: Key, ctx: AddressContext) {
        match self.active_locations.entry((key, ctx)) {
            Entry::Occupied(mut entry) => {
                let locations = entry.get_mut();
                let location_was_removed = locations.remove(&(view, gfn));
                debug_assert!(location_was_removed);

                if locations.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {
                panic!("trying to remove an active location that is not registered");
            }
        }
    }

    /// Removes a breakpoint while treating a destroyed view as already clean.
    fn remove_controller_breakpoint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        pa: Pa,
        view: View,
    ) -> Result<(), VmiError> {
        match self.controller.remove_breakpoint(vmi, pa, view) {
            Ok(()) | Err(VmiError::ViewNotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Stops monitoring a page while tolerating a destroyed view.
    fn unmonitor_controller_page(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        match self.controller.unmonitor(vmi, gfn, view) {
            Ok(()) | Err(VmiError::ViewNotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Restores physical breakpoints removed by a failed group operation.
    fn restore_controller_breakpoints(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        view: View,
        breakpoints: &[(Key, AddressContext, Pa)],
    ) {
        for &(_, _, pa) in breakpoints {
            if let Err(err) = self.controller.insert_breakpoint(vmi, pa, view) {
                tracing::error!(
                    %err,
                    %pa,
                    %view,
                    "failed to restore breakpoint after group removal failure"
                );
            }
        }
    }

    fn pa_from_gfn_and_va(&self, gfn: Gfn, va: Va) -> Pa {
        <Interface::Driver as VmiDriver>::Architecture::pa_from_gfn(gfn)
            + <Interface::Driver as VmiDriver>::Architecture::va_offset(va)
    }

    fn address_for_event(
        &self,
        event: &VmiEvent<<Interface::Driver as VmiDriver>::Architecture>,
    ) -> Option<(AddressContext, Pa, View)> {
        let (view, gfn) = match self.controller.check_event(event) {
            Some((view, gfn)) => (view, gfn),
            None => return None,
        };

        let ip = Va(event.registers().instruction_pointer());
        let pa = self.pa_from_gfn_and_va(gfn, ip);

        //
        // If there is a global breakpoint for this address, fix the root
        // with the one it was registered with.
        //

        let root = match self.active_global_breakpoints.get(&(view, ip)) {
            Some(global_breakpoint) => global_breakpoint.root,
            None => event.registers().translation_root(ip),
        };

        let ctx = AddressContext::new(ip, root);

        Some((ctx, pa, view))
    }
}

/// Verifies breakpoint definitions, controllers, and manager behavior.
#[cfg(all(test, feature = "arch-amd64"))]
mod tests;
