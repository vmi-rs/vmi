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
//! # Consistency on error
//!
//! Inserting, removing, and clearing breakpoints each perform several VMI
//! operations through the controller while updating the manager's internal
//! bookkeeping, and none of this is applied as a single transaction. If an
//! underlying operation fails, the steps that already succeeded are not undone,
//! and the manager's tracking maps can be left out of sync with the physical
//! breakpoints in the guest. Most methods surface this by returning an error,
//! [`clear`] instead logs the desync and continues. Either way, treat the VM
//! as being in an undefined state and do not assume a failed call had no
//! effect.
//!
//! [`clear`]: BreakpointManager::clear
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

#[cfg(test)]
mod tests;

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
    ///   (Key, AddressContext)
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
    /// * Key: (View, AddressContext)
    /// * Value: Map of pending breakpoints for that address, one per owning key
    ///
    /// Breakpoints move between `active_breakpoints` and `pending_breakpoints`
    /// based on page-in and page-out events.
    pending_breakpoints: HashMap<(View, AddressContext), PendingBreakpoints<Key, Tag>>,

    /// Maps pending breakpoints to their views.
    /// This map is used to quickly remove pending breakpoints when a view is
    /// removed.
    ///
    /// * Key: View
    /// * Value: Set of addresses with pending breakpoints in this view
    ///
    /// This map is kept in sync with `pending_breakpoints`.
    pending_ctx_by_view: HashMap<View, HashSet<AddressContext>>,

    /// Controller used to insert and remove breakpoints.
    controller: Controller,
}

#[derive(Debug)]
struct GlobalBreakpoint {
    /// Canonical translation root shared by every breakpoint at this VA.
    root: Pa,

    /// Reference-counted physical pages backing this global VA.
    ///
    /// * Key: GFN
    /// * Value: Number of active breakpoints at this VA that resolve to the GFN
    ///
    /// A page shared by several breakpoints stays registered until its last
    /// breakpoint is removed.
    gfns: HashMap<Gfn, usize>,
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
            None => return self.insert_pending_breakpoint(breakpoint),
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
    /// A global breakpoint is matched by the canonical root registered for its
    /// virtual address, so it can be removed with any of the roots it was
    /// inserted with.
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
        let Breakpoint {
            mut ctx,
            view,
            global,
            key,
            ..
        } = breakpoint;

        // Removing a pending breakpoint only affects the requested key, leaving
        // pending breakpoints registered under other keys at the same address
        // in place. The pending copy is keyed by the context the caller
        // registered it with, so it is looked up before the root is folded
        // below.
        //
        // A global breakpoint can hold a pending copy under one root and an
        // active copy under the canonical root at the same time, so removing the
        // pending copy must not stop the teardown of the active one. Otherwise a
        // successful return could leave an installed breakpoint behind.
        let pending_removed = self.remove_pending_breakpoint(ctx, view, key);

        let pa = match pa {
            Some(pa) => pa,
            None => return Ok(pending_removed),
        };

        //
        // Insertion folds the root of a global breakpoint onto the canonical
        // root registered for its virtual address, so the lookup below has to
        // fold it the same way. Without this, a global breakpoint inserted
        // under a second root cannot be removed with that root.
        //

        if global
            && let Some(global_breakpoint) = self.active_global_breakpoints.get(&(view, ctx.va))
        {
            ctx.root = global_breakpoint.root;
        }

        let active_removed = self
            .remove_active_breakpoint(vmi, ctx, pa, key, view)?
            .is_some();

        Ok(pending_removed || active_removed)
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
        //
        // First remove all pending breakpoints for this view (if any).
        //

        let mut removed = false;

        if let Some(pending_ctxs) = self.pending_ctx_by_view.remove(&view) {
            for ctx in pending_ctxs {
                self.remove_pending_breakpoints_by_address(ctx, view);
            }

            removed = true;
        };

        //
        // Then remove all active breakpoints for this view.
        //

        let gfns = match self.active_gfns_by_view.remove(&view) {
            Some(gfns) => gfns,
            None => return Ok(removed),
        };

        //
        // Set of GFNs should never be empty.
        //

        debug_assert!(!gfns.is_empty(), "active_gfns_by_view is empty");

        for gfn in gfns {
            self.remove_active_breakpoints_by_location(vmi, gfn, view)?;
        }

        Ok(true)
    }

    /// Returns the breakpoint registered under `key` for the given event.
    pub fn get_by_event(
        &self,
        event: &VmiEvent<<Interface::Driver as VmiDriver>::Architecture>,
        key: Key,
    ) -> Option<Breakpoint<Key, Tag>> {
        let (ctx, pa, view) = self.address_for_event(event)?;
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        let breakpoints_by_ctx = self.active_breakpoints.get(&(view, gfn))?;
        let breakpoint = breakpoints_by_ctx.get(&(key, ctx))?;

        Some(*breakpoint)
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
        let mut to_remove = Vec::new();

        for (&(view, gfn), breakpoints) in &self.active_breakpoints {
            for &(key, ctx) in breakpoints.keys() {
                let pa = self.pa_from_gfn_and_va(gfn, ctx.va);
                to_remove.push((key, view, pa, ctx));
            }
        }

        self.pending_breakpoints.clear();
        self.pending_ctx_by_view.clear();

        for (key, view, pa, ctx) in to_remove {
            if let Err(err) = self.remove_active_breakpoint(vmi, ctx, pa, key, view) {
                tracing::error!(
                    %err, %pa, %ctx, %view, ?key,
                    "failed to remove breakpoint"
                );
            }
        }

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

        for breakpoint in breakpoints.into_values() {
            self.insert_active_breakpoint(vmi, breakpoint, pa)?;
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

        for breakpoint in breakpoints_by_ctx.into_values() {
            self.insert_pending_breakpoint(breakpoint)?;
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
        breakpoint: Breakpoint<Key, Tag>,
        pa: Pa,
    ) -> Result<bool, VmiError> {
        //
        // The code in this function roughly follows the following logic:
        //
        // let breakpoint_was_inserted = self
        //     .active_breakpoints
        //     .entry((view, gfn))
        //     .or_default()
        //     .entry((key, ctx))
        //     .or_default()
        //     .insert(tag);
        //
        // self.gfns_for_address.insert((key, ctx), (view, gfn))
        //
        // Except that:
        // - breakpoint_was_inserted is true ONLY if the breakpoint was inserted
        //   (i.e., not just updated with a new tag)
        // - asserts are used to ensure that the internal state is consistent
        //

        let Breakpoint {
            mut ctx,
            view,
            global,
            key,
            tag,
        } = breakpoint;
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        //
        // If this breakpoint should be global, fold its root onto the canonical
        // root already registered for this global VA, so all roots collapse onto
        // a single active breakpoint. The page is registered only once the
        // breakpoint is confirmed to be newly inserted, further below, so
        // duplicates do not inflate the page reference count.
        //

        if global
            && let Some(global_breakpoint) = self.active_global_breakpoints.get(&(view, ctx.va))
        {
            ctx.root = global_breakpoint.root;
        }

        //
        // An address already claimed by this key keeps the breakpoint it was
        // claimed with, so the claim cannot be reinterpreted under it. The check
        // runs before anything is mutated, leaving a rejected insertion without
        // an effect.
        //

        if let Some(breakpoints) = self.active_breakpoints.get(&(view, gfn))
            && let Some(existing) = breakpoints.get(&(key, ctx))
        {
            self.check_existing_breakpoint(existing, &breakpoint)?;
        }

        // Activating a breakpoint supersedes any pending copy of it, so the
        // same breakpoint is never both pending and active at once.
        self.remove_pending_breakpoint(breakpoint.ctx, view, key);

        //
        // page_was_inserted is true if a new `(view, GFN)` pair was inserted
        // breakpoint_was_inserted is true if a new `(key, ctx)` pair was inserted
        //

        let (breakpoint_was_inserted, page_was_inserted) =
            match self.active_breakpoints.entry((view, gfn)) {
                Entry::Occupied(mut entry) => {
                    let breakpoints = entry.get_mut();

                    match breakpoints.entry((key, ctx)) {
                        Entry::Occupied(_) => (false, false),
                        Entry::Vacant(entry) => {
                            entry.insert(breakpoint);
                            (true, false)
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(HashMap::from([((key, ctx), breakpoint)]));
                    (true, true)
                }
            };

        if breakpoint_was_inserted {
            tracing::debug!(
                active = self.active_breakpoints.len(),
                %gfn, %ctx, %view, %global, ?key, ?tag,
                "active breakpoint inserted"
            );

            //
            // Register the page under the global VA. A claim keeps the global
            // flag it was made with, so this pairs one-to-one with the release
            // in `uninstall_breakpoint`.
            //

            if global {
                self.register_global_breakpoint(gfn, view, ctx.root, ctx.va);
            }

            //
            // REVIEW:
            // Should monitor + insert_breakpoint be atomic? (i.e., should we
            // consider vmi.pause() + vmi.resume()?)
            //

            //
            // Update the monitored GFNs.
            // Also, verify that the monitored GFNs are consistent with the
            // active breakpoints.
            //

            self.install_breakpoint(vmi, pa, view, key, ctx)?;

            //
            // If this is a new `(view, GFN)` pair, it needs to be monitored.
            //
            // IMPORTANT: It is important to monitor the page AFTER the
            //            breakpoint is inserted. Otherwise, the page access
            //            might change during the GFN remapping.
            //

            if page_was_inserted {
                self.monitor_page_for_changes(vmi, gfn, view)?;
            }
        }
        else {
            //
            // If the breakpoint was not inserted, it means it is already
            // in the active breakpoints.
            //
            // Verify that the monitored GFNs are consistent.
            //

            debug_assert!(
                self.active_locations.contains_key(&(key, ctx)),
                "desynchronized active breakpoints and monitored gfns"
            );
        }

        Ok(breakpoint_was_inserted)
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
        //
        // First check if this `(view, GFN)` already has a breakpoint.
        //

        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        let mut gfn_entry = match self.active_breakpoints.entry((view, gfn)) {
            Entry::Occupied(gfn_entry) => gfn_entry,
            Entry::Vacant(_) => return Ok(None),
        };

        //
        // If this `(view, GFN)` has a breakpoint, verify that the monitored
        // locations are consistent with the active breakpoints.
        //

        debug_assert!(
            self.active_gfns_by_view.contains_key(&view)
                && self.active_gfns_by_view[&view].contains(&gfn),
            "desynchronized active_breakpoints and active_gfns_by_view"
        );

        let ctx = ctx.into();

        //
        // This `(view, GFN)` has a breakpoint.
        // Check if the specified `(key, ctx)` has a breakpoint.
        //

        let breakpoints_by_ctx = gfn_entry.get_mut();

        let breakpoint = match breakpoints_by_ctx.remove(&(key, ctx)) {
            Some(breakpoint) => breakpoint,
            None => {
                //
                // This `(key, ctx)` doesn't have a breakpoint for this `(view, GFN)`.
                // Keep the breakpoint for the current `(view, GFN)`.
                //
                // Also, verify that the active locations are consistent with the
                // active breakpoints.
                //

                if !self.active_locations.contains_key(&(key, ctx)) {
                    tracing::debug!(
                        %gfn, %ctx, %view, ?key,
                        "breakpoint not found for key"
                    );
                }
                else {
                    tracing::error!(
                        %gfn, %ctx, %view, ?key,
                        "breakpoint not found for key"
                    );
                }

                debug_assert!(
                    !self.active_locations.contains_key(&(key, ctx)),
                    "desynchronized active_breakpoints and active_locations"
                );

                return Ok(None);
            }
        };

        let global = breakpoint.global;
        let last_breakpoint_removed = breakpoints_by_ctx.is_empty();

        if last_breakpoint_removed {
            //
            // There are no more breakpoints registered for this `(view, GFN)`.
            // Remove the breakpoint for the current `(view, GFN)`.
            //

            tracing::debug!(
                %gfn, %ctx, %view, ?key, ?breakpoint,
                "breakpoint removed"
            );

            gfn_entry.remove();
        }
        else {
            //
            // There are still other breakpoints registered for this `(view, GFN)`.
            // Keep the breakpoint for the current `(view, GFN)`.
            //

            tracing::debug!(
                %gfn, %ctx, %view, ?key,
                remaining = breakpoints_by_ctx.len(),
                "breakpoint still in use"
            );
        }

        self.uninstall_breakpoint(vmi, pa, view, key, ctx, global)?;

        if last_breakpoint_removed {
            //
            // Because there are no more breakpoints for this `(view, GFN)`,
            // unmonitor the `(view, GFN)` pair.
            //
            // IMPORTANT: It is important to unmonitor the page AFTER the
            //            breakpoint is removed. Otherwise, the page access
            //            might change during the GFN remapping.
            //

            self.unmonitor_page_for_changes(vmi, gfn, view)?;
        }

        Ok(Some(last_breakpoint_removed))
    }

    /// Removes all active breakpoints for a given `(view, GFN)` pair.
    fn remove_active_breakpoints_by_location(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<Option<ActiveBreakpoints<Key, Tag>>, VmiError> {
        let breakpoints = match self.active_breakpoints.remove(&(view, gfn)) {
            Some(breakpoints) => breakpoints,
            None => return Ok(None),
        };

        //
        // REVIEW:
        // Should remove_breakpoint + unmonitor be atomic? (i.e., should we
        // consider vmi.pause() + vmi.resume()?)
        //

        for (&(key, ctx), breakpoint) in &breakpoints {
            let pa = self.pa_from_gfn_and_va(gfn, ctx.va);
            self.uninstall_breakpoint(vmi, pa, view, key, ctx, breakpoint.global)?;
        }

        tracing::debug!(
            active = self.active_breakpoints.len(),
            %gfn,
            %view,
            ?breakpoints,
            "active breakpoints removed"
        );

        self.unmonitor_page_for_changes(vmi, gfn, view)?;

        Ok(Some(breakpoints))
    }

    /// Inserts a pending breakpoint.
    ///
    /// Returns `true` if the breakpoint was newly inserted, `false` if it was
    /// already present.
    fn insert_pending_breakpoint(
        &mut self,
        breakpoint: Breakpoint<Key, Tag>,
    ) -> Result<bool, VmiError> {
        let Breakpoint {
            ctx,
            view,
            global,
            key,
            tag,
            ..
        } = breakpoint;

        //
        // As on the active side, an address already claimed by this key keeps
        // the breakpoint it was claimed with. Rejecting the conflict here also
        // keeps it out of `handle_page_in`, which would otherwise fail while
        // restoring a pending breakpoint.
        //

        if let Some(breakpoints) = self.pending_breakpoints.get(&(view, ctx))
            && let Some(existing) = breakpoints.get(&key)
        {
            self.check_existing_breakpoint(existing, &breakpoint)?;
        }

        let result = match self
            .pending_breakpoints
            .entry((view, ctx))
            .or_default()
            .entry(key)
        {
            Entry::Occupied(_) => {
                //
                // This key already claims the address, so the per-view index
                // must already list its context. Checked here rather than after
                // the match, because the index insertion below would repair a
                // desync without reporting it.
                //

                debug_assert!(
                    self.pending_ctx_by_view.contains_key(&view)
                        && self.pending_ctx_by_view[&view].contains(&ctx),
                    "desynchronized pending_breakpoints and pending_ctx_by_view"
                );

                false
            }
            Entry::Vacant(entry) => {
                entry.insert(breakpoint);
                true
            }
        };

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

        Ok(result)
    }

    /// Removes all pending breakpoints for a given `(view, ctx)` pair, along
    /// with the `ctx` entry in the per-view pending index.
    ///
    /// Callers that empty a `(view, ctx)` entry themselves must finish through
    /// this function rather than removing the entry directly.
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

    /// Removes the pending breakpoint claimed by `key` at `(view, ctx)`.
    ///
    /// Pending breakpoints registered under other keys at the same address are
    /// left in place.
    ///
    /// Returns `true` if one was removed.
    fn remove_pending_breakpoint(&mut self, ctx: AddressContext, view: View, key: Key) -> bool {
        let breakpoints = match self.pending_breakpoints.get_mut(&(view, ctx)) {
            Some(breakpoints) => breakpoints,
            None => return false,
        };

        if breakpoints.remove(&key).is_none() {
            return false;
        }

        if breakpoints.is_empty() {
            self.remove_pending_breakpoints_by_address(ctx, view);
        }

        true
    }

    /// Records that the global VA `(view, va)` is installed on `gfn`.
    ///
    /// Creates the entry with `root` as its canonical root on first use, and
    /// bumps the page's reference count so a page shared by several global
    /// breakpoints survives until the last one is removed.
    fn register_global_breakpoint(&mut self, gfn: Gfn, view: View, root: Pa, va: Va) {
        let global_breakpoint = self
            .active_global_breakpoints
            .entry((view, va))
            .or_insert_with(|| GlobalBreakpoint {
                root,
                gfns: HashMap::new(),
            });

        *global_breakpoint.gfns.entry(gfn).or_insert(0) += 1;
    }

    /// Releases one reference to `gfn` for the global VA `(view, va)`.
    ///
    /// Does nothing when the VA has no global entry or the page is not
    /// registered, so it is safe to call for non-global removals. Drops the page
    /// when its reference count reaches zero and the whole entry when its last
    /// page is gone.
    fn unregister_global_breakpoint(&mut self, gfn: Gfn, view: View, va: Va) {
        let mut entry = match self.active_global_breakpoints.entry((view, va)) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return,
        };

        let global_breakpoint = entry.get_mut();
        match global_breakpoint.gfns.get_mut(&gfn) {
            Some(references) => {
                *references -= 1;
                if *references == 0 {
                    global_breakpoint.gfns.remove(&gfn);
                }
            }
            None => return,
        }

        if global_breakpoint.gfns.is_empty() {
            entry.remove();
        }
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

    fn monitor_page_for_changes(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        self.insert_monitored_location(gfn, view);
        self.controller.monitor(vmi, gfn, view)
    }

    fn unmonitor_page_for_changes(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError> {
        self.remove_monitored_location(gfn, view);
        match self.controller.unmonitor(vmi, gfn, view) {
            Ok(()) => Ok(()),
            Err(VmiError::ViewNotFound) => {
                //
                // The view was not found. This can happen if the view was
                // destroyed before the breakpoint was removed.
                //
                // In this case, we can safely ignore the error.
                //
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn install_breakpoint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        pa: Pa,
        view: View,
        key: Key,
        ctx: AddressContext,
    ) -> Result<(), VmiError> {
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);
        let view_gfn_was_inserted = self
            .active_locations
            .entry((key, ctx))
            .or_default()
            .insert((view, gfn));

        debug_assert!(
            view_gfn_was_inserted,
            "trying to install a breakpoint that is already installed"
        );

        self.controller.insert_breakpoint(vmi, pa, view)
    }

    fn uninstall_breakpoint(
        &mut self,
        vmi: &VmiCore<Interface::Driver>,
        pa: Pa,
        view: View,
        key: Key,
        ctx: AddressContext,
        global: bool,
    ) -> Result<(), VmiError> {
        let gfn = <Interface::Driver as VmiDriver>::Architecture::gfn_from_pa(pa);

        // Only global breakpoints have global bookkeeping. Calling this for a
        // non-global breakpoint that happens to share a VA with a global one
        // would otherwise release the global's page reference by mistake.
        if global {
            self.unregister_global_breakpoint(gfn, view, ctx.va);
        }

        match self.active_locations.entry((key, ctx)) {
            Entry::Occupied(mut entry) => {
                let view_gfns = entry.get_mut();
                let view_gfn_was_removed = view_gfns.remove(&(view, gfn));
                debug_assert!(
                    view_gfn_was_removed,
                    "trying to uninstall a breakpoint that is not installed"
                );

                if view_gfns.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {
                panic!("trying to uninstall a breakpoint that is not installed");
            }
        }

        match self.controller.remove_breakpoint(vmi, pa, view) {
            Ok(()) => Ok(()),
            Err(VmiError::ViewNotFound) => {
                //
                // The view was not found. This can happen if the view was
                // destroyed before the breakpoint was removed.
                //
                // In this case, we can safely ignore the error.
                //
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Checks `new_breakpoint` against the claim `existing_breakpoint` already
    /// holds on the same key and address.
    ///
    /// An address holds one breakpoint per key, so a repeated insertion cannot
    /// restate what that breakpoint is. Disagreeing on the global flag would
    /// change when the installed breakpoint matches, which is rejected. A
    /// disagreeing tag only relabels the same claim, so the existing tag is
    /// kept and the new one is reported.
    fn check_existing_breakpoint(
        &self,
        existing_breakpoint: &Breakpoint<Key, Tag>,
        new_breakpoint: &Breakpoint<Key, Tag>,
    ) -> Result<(), VmiError> {
        if existing_breakpoint.global != new_breakpoint.global {
            return Err(VmiError::Other(
                "breakpoint already registered with a different global flag",
            ));
        }

        if existing_breakpoint.tag != new_breakpoint.tag {
            tracing::debug!(
                ctx = %existing_breakpoint.ctx,
                view = %existing_breakpoint.view,
                key = ?existing_breakpoint.key,
                existing_tag = ?existing_breakpoint.tag,
                new_tag = ?new_breakpoint.tag,
                "breakpoint already registered, keeping the existing tag"
            );
        }

        Ok(())
    }

    fn pa_from_gfn_and_va(&self, gfn: Gfn, va: Va) -> Pa {
        <Interface::Driver as VmiDriver>::Architecture::pa_in_gfn(gfn, va)
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
