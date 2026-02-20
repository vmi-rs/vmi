//! AMD64 page table monitor implementation.
//!
//! Implements page table monitoring for the AMD64 4-level paging hierarchy
//! (PML4 → PDPT → PD → PT → Data), including support for 2MB (PD-level)
//! and 1GB (PDPT-level) large pages.
//!
//! # Architecture
//!
//! The implementation maintains three indexes:
//!
//! - **VA index** (`vas`): Maps each monitored virtual address (identified by
//!   [`AddressContext`] and [`View`]) to its state: the tag, walk chain of
//!   entry keys, paged-in status, and resolved physical address.
//!
//! - **Entry index** (`entries`): Maps each monitored page table entry
//!   (identified by its physical address and [`View`]) to the cached PTE
//!   value and a map of dependent VAs to their page table levels. The
//!   level is stored per-VA because different roots can map the same
//!   physical page at different hierarchy levels. Entries back-reference
//!   VAs for efficient dirty processing.
//!
//! - **Table index** (`tables`): Maps each write-protected page table page
//!   (identified by [`Gfn`] and [`View`]) to a reference count of monitored
//!   entries within it. Write protection is applied when the first entry on a
//!   page is monitored, and removed when the last is unmonitored.
//!
//! # Dirty Processing Order
//!
//! When a write to a monitored page table page is detected via an EPT
//! violation, the affected entry is marked dirty. During processing, dirty
//! entries are sorted by page table level (highest first) to correctly handle
//! cascading invalidations: when a PD entry becomes not-present, the entire
//! PT subtree below it is invalidated. Processing the PD entry first removes
//! the PT monitoring, so the stale PT dirty entry is safely skipped.

use std::collections::{HashMap, HashSet};

use vmi_arch_amd64::{Amd64, PageTableEntry, PageTableLevel};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId,
    View, VmiCore, VmiError,
    driver::{VmiRead, VmiSetProtection},
};

use super::{
    super::{PageEntryUpdate, PageTableMonitorEvent, TagType},
    ArchAdapter, PageTableMonitorArchAdapter,
};

// ─── Key Types ───────────────────────────────────────────────────────────────

/// Identifies a monitored virtual address within a specific view: `(View, AddressContext)`.
type VaKey = (View, AddressContext);

/// Identifies a monitored page table entry within a specific view: `(View, Pa)`.
type EntryKey = (View, Pa);

/// Identifies a write-protected page table page within a specific view: `(View, Gfn)`.
type TableKey = (View, Gfn);

// ─── Internal State ─────────────────────────────────────────────────────────

/// Per-VA monitoring state.
struct MonitoredVa<Tag> {
    tag: Tag,
    /// Whether the full translation chain resolves to a data page.
    paged_in: bool,
    /// Resolved physical address (valid when `paged_in` is true).
    resolved_pa: Option<Pa>,
    /// Entry chain from PML4 down to the deepest monitored level.
    entry_keys: Vec<EntryKey>,
}

/// Per-entry monitoring state.
struct MonitoredEntry {
    /// Last-known PTE value read from guest memory.
    cached_pte: PageTableEntry,
    /// VAs that traverse this entry, each with its page table level.
    ///
    /// The level is stored per-VA rather than per-entry because different
    /// page table hierarchies (different roots) can map the same physical
    /// address at different levels (e.g., one root uses a page as a PD
    /// table while another uses it as a PT table).
    va_levels: HashMap<VaKey, PageTableLevel>,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Returns `true` if this PTE terminates the page walk (leaf PT level or
/// large page at a higher level).
fn is_leaf(level: PageTableLevel, pte: PageTableEntry) -> bool {
    level == PageTableLevel::Pt || pte.large()
}

/// Computes the resolved physical address for a leaf PTE.
fn leaf_pa(va: Va, level: PageTableLevel, pfn: Gfn) -> Pa {
    Amd64::pa_from_gfn(pfn) + Amd64::va_offset_for(va, level)
}

/// Reads a single page table entry from guest physical memory.
fn read_pte<Driver>(vmi: &VmiCore<Driver>, pa: Pa) -> Result<PageTableEntry, VmiError>
where
    Driver: VmiRead,
{
    vmi.read_struct(pa)
}

// ─── ArchAdapter ────────────────────────────────────────────────────────────

impl<Driver, Tag> ArchAdapter<Driver, Tag> for Amd64
where
    Driver: VmiRead + VmiSetProtection<Architecture = Amd64>,
    Tag: TagType,
{
    type Impl = Amd64PageTableMonitor<Tag>;
}

// ─── AMD64 Page Table Monitor ───────────────────────────────────────────────

/// AMD64 page table monitor.
///
/// Tracks page table entry changes across the 4-level paging hierarchy and
/// generates [`PageTableMonitorEvent`]s when monitored virtual addresses gain
/// or lose physical memory backing.
pub struct Amd64PageTableMonitor<Tag>
where
    Tag: TagType,
{
    /// Monitored virtual addresses.
    vas: HashMap<VaKey, MonitoredVa<Tag>>,
    /// Monitored page table entries with bidirectional VA references.
    entries: HashMap<EntryKey, MonitoredEntry>,
    /// Write-protected page table pages with reference counts.
    tables: HashMap<TableKey, usize>,
    /// Dirty entries pending processing, tracked per-vCPU.
    ///
    /// Dirty entries must be per-vCPU because the singlestep mechanism is
    /// per-vCPU: when vCPU A writes to a page table page, only vCPU A is
    /// singlestepped and only vCPU A's write is guaranteed to be committed
    /// by the time `process_dirty_entries` runs. If a global collection
    /// were used, vCPU B could steal vCPU A's dirty entry and re-read the
    /// PTE before vCPU A's write completes, producing stale or partially-
    /// written GFN values.
    dirty: HashMap<VcpuId, HashSet<EntryKey>>,
}

// ─── Private Implementation ─────────────────────────────────────────────────

impl<Tag> Amd64PageTableMonitor<Tag>
where
    Tag: TagType,
{
    /// Begins write-protecting a table page or increments its reference count.
    fn add_table_ref<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        gfn: Gfn,
        view: View,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiSetProtection,
    {
        let table_key = (view, gfn);
        let refcount = self.tables.entry(table_key).or_insert(0);
        if *refcount == 0 {
            vmi.set_memory_access_with_options(
                gfn,
                view,
                MemoryAccess::R,
                MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES,
            )?;
        }
        *refcount += 1;
        Ok(())
    }

    /// Decrements a table page's reference count, restoring full memory
    /// access when the count reaches zero. Handles `ViewNotFound` gracefully
    /// in case the view was destroyed before unmonitoring.
    fn remove_table_ref<Driver>(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View)
    where
        Driver: VmiRead + VmiSetProtection,
    {
        let table_key = (view, gfn);
        if let Some(refcount) = self.tables.get_mut(&table_key) {
            *refcount -= 1;
            if *refcount == 0 {
                self.tables.remove(&table_key);
                match vmi.set_memory_access(gfn, view, MemoryAccess::RW) {
                    Ok(()) | Err(VmiError::ViewNotFound) => {}
                    Err(err) => {
                        tracing::warn!(%gfn, %view, %err, "failed to restore memory access");
                    }
                }
            }
        }
    }

    /// Removes a VA's dependency from an entry. If the entry has no more
    /// dependents, removes it and decrements the table reference count.
    fn detach_va_from_entry<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        va_key: VaKey,
        (view, pa): EntryKey,
    ) where
        Driver: VmiRead + VmiSetProtection,
    {
        let entry_key = (view, pa);
        let entry = match self.entries.get_mut(&entry_key) {
            Some(entry) => entry,
            None => return,
        };

        entry.va_levels.remove(&va_key);

        if entry.va_levels.is_empty() {
            self.entries.remove(&entry_key);
            self.remove_table_ref(vmi, Amd64::gfn_from_pa(pa), view);
        }
    }

    /// Removes all entries below the anchor entry in a VA's walk chain.
    /// Used when a higher-level entry changes and invalidates the subtree.
    fn tear_down_subtree<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        va_key: VaKey,
        anchor_key: EntryKey,
    ) where
        Driver: VmiRead + VmiSetProtection,
    {
        let va = match self.vas.get_mut(&va_key) {
            Some(va) => va,
            None => return,
        };

        let pos = match va.entry_keys.iter().position(|k| *k == anchor_key) {
            Some(pos) => pos,
            None => {
                debug_assert!(
                    false,
                    "tear_down_subtree: anchor {anchor_key:?} not found in VA {va_key:?} entry_keys"
                );
                return;
            }
        };

        let removed: Vec<EntryKey> = va.entry_keys.drain(pos + 1..).collect();
        for ek in removed {
            self.detach_va_from_entry(vmi, va_key, ek);
        }
    }

    /// Walks page table levels below `parent_level`, starting from
    /// `start_gfn`. Registers new entries and emits a PageIn event if the
    /// walk resolves to a leaf.
    fn walk_subtree<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        (view, ctx): VaKey,
        start_gfn: Gfn,
        parent_level: PageTableLevel,
        events: &mut Vec<PageTableMonitorEvent>,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiSetProtection,
    {
        let va_key = (view, ctx);
        let mut current_gfn = start_gfn;
        let mut level_opt = parent_level.next();

        while let Some(level) = level_opt {
            let index = Amd64::va_index_for(ctx.va, level);
            let entry_pa = Amd64::pa_from_gfn(current_gfn) + index * 8;
            let entry_key = (view, entry_pa);

            if !self.entries.contains_key(&entry_key) {
                self.add_table_ref(vmi, current_gfn, view)?;
            }

            let pte = read_pte(vmi, entry_pa)?;

            let entry = self.entries.entry(entry_key).or_insert(MonitoredEntry {
                cached_pte: pte,
                va_levels: HashMap::new(),
            });
            // Don't overwrite cached_pte if the entry already existed — another
            // VA may have a pending dirty entry for it, and overwriting would
            // mask the old→new PTE change during dirty processing.
            // entry.cached_pte = pte;
            entry.va_levels.insert(va_key, level);

            self.vas
                .get_mut(&va_key)
                .unwrap()
                .entry_keys
                .push(entry_key);

            if !pte.present() {
                break;
            }

            if is_leaf(level, pte) {
                let pa = leaf_pa(ctx.va, level, pte.pfn());
                let va = self.vas.get_mut(&va_key).unwrap();
                va.paged_in = true;
                va.resolved_pa = Some(pa);
                events.push(PageTableMonitorEvent::PageIn(PageEntryUpdate {
                    view,
                    ctx,
                    pa,
                }));
                break;
            }

            current_gfn = pte.pfn();
            level_opt = level.next();
        }

        Ok(())
    }
}

// ─── PageTableMonitorArchAdapter ────────────────────────────────────────────

impl<Driver, Tag> PageTableMonitorArchAdapter<Driver, Tag> for Amd64PageTableMonitor<Tag>
where
    Driver: VmiRead + VmiSetProtection<Architecture = Amd64>,
    Tag: TagType,
{
    fn new() -> Self {
        Self {
            vas: HashMap::new(),
            entries: HashMap::new(),
            tables: HashMap::new(),
            dirty: HashMap::new(),
        }
    }

    fn monitored_tables(&self) -> usize {
        self.tables.len()
    }

    fn monitored_entries(&self) -> usize {
        self.entries.len()
    }

    fn paged_in_entries(&self) -> usize {
        self.vas.values().filter(|va| va.paged_in).count()
    }

    fn dump(&self) {
        tracing::debug!(
            tables = self.tables.len(),
            entries = self.entries.len(),
            vas = self.vas.len(),
            paged_in = self.vas.values().filter(|va| va.paged_in).count(),
            "page table monitor state"
        );
        for (&(view, ctx), va) in &self.vas {
            tracing::debug!(
                va = %ctx.va,
                root = %ctx.root,
                view = %view,
                tag = ?va.tag,
                paged_in = va.paged_in,
                resolved_pa = ?va.resolved_pa,
                chain_len = va.entry_keys.len(),
                "  monitored VA"
            );
        }
    }

    fn monitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
        tag: Tag,
    ) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let va_key = (view, ctx);

        // Re-monitoring: tear down existing state first.
        if self.vas.contains_key(&va_key) {
            self.unmonitor(vmi, ctx, view)?;
        }

        let mut entry_keys = Vec::new();
        let mut current_gfn = Amd64::gfn_from_pa(ctx.root);
        let mut paged_in = false;
        let mut resolved_pa = None;

        let mut level_opt = Some(PageTableLevel::Pml4);
        while let Some(level) = level_opt {
            let index = Amd64::va_index_for(ctx.va, level);
            let entry_pa = Amd64::pa_from_gfn(current_gfn) + index * 8;
            let entry_key = (view, entry_pa);

            if !self.entries.contains_key(&entry_key) {
                self.add_table_ref(vmi, current_gfn, view)?;
            }

            let pte = read_pte(vmi, entry_pa)?;

            let entry = self.entries.entry(entry_key).or_insert(MonitoredEntry {
                cached_pte: pte,
                va_levels: HashMap::new(),
            });
            entry.cached_pte = pte;
            entry.va_levels.insert(va_key, level);

            entry_keys.push(entry_key);

            if !pte.present() {
                break;
            }

            if is_leaf(level, pte) {
                resolved_pa = Some(leaf_pa(ctx.va, level, pte.pfn()));
                paged_in = true;
                break;
            }

            current_gfn = pte.pfn();
            level_opt = level.next();
        }

        self.vas.insert(
            va_key,
            MonitoredVa {
                tag,
                paged_in,
                resolved_pa,
                entry_keys,
            },
        );

        Ok(())
    }

    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let va_key = (view, ctx);

        let va = match self.vas.remove(&va_key) {
            Some(va) => va,
            None => return Ok(()),
        };

        for entry_key in va.entry_keys {
            self.detach_va_from_entry(vmi, va_key, entry_key);
        }

        Ok(())
    }

    fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>) {
        for &(view, gfn) in self.tables.keys() {
            let _ = vmi.set_memory_access(gfn, view, MemoryAccess::RW);
        }
        self.tables.clear();
        self.entries.clear();
        self.vas.clear();
        self.dirty.clear();
    }

    fn unmonitor_view(&mut self, vmi: &VmiCore<Driver>, view: View) {
        let va_keys: Vec<VaKey> = self
            .vas
            .keys()
            .filter(|&&(v, _)| v == view)
            .copied()
            .collect();

        for (v, ctx) in va_keys {
            debug_assert_eq!(v, view);
            let _ = self.unmonitor(vmi, ctx, view);
        }
    }

    fn mark_dirty_entry(&mut self, entry_pa: Pa, view: View, vcpu_id: VcpuId) -> bool {
        let entry_key = (view, entry_pa);

        if !self.entries.contains_key(&entry_key) {
            return false;
        }

        self.dirty.entry(vcpu_id).or_default().insert(entry_key)
    }

    fn process_dirty_entries(
        &mut self,
        vmi: &VmiCore<Driver>,
        vcpu_id: VcpuId,
    ) -> Result<Vec<PageTableMonitorEvent>, VmiError> {
        let dirty_keys = self.dirty.remove(&vcpu_id).unwrap_or_default();

        // Resolve levels.
        let mut to_process: Vec<(EntryKey, PageTableLevel)> = Vec::new();

        for key in dirty_keys {
            if let Some(entry) = self.entries.get(&key) {
                // Use the highest level across all VAs for sort priority.
                let max_level = entry.va_levels.values().copied().max().unwrap();
                to_process.push((key, max_level));
            }
        }

        // Sort by level descending (PML4 first, PT last) to ensure
        // higher-level changes invalidate subtrees before lower-level
        // entries are processed.
        to_process.sort_by(|a, b| b.1.cmp(&a.1));

        let mut events = Vec::new();

        for (entry_key, _) in to_process {
            // Re-check: a higher-level change may have removed this entry.
            let entry = match self.entries.get(&entry_key) {
                Some(entry) => entry,
                None => continue,
            };

            let old_pte = entry.cached_pte;
            let (_, entry_pa) = entry_key;
            let new_pte = read_pte(vmi, entry_pa)?;

            if old_pte == new_pte {
                continue;
            }

            // Update cached PTE.
            self.entries.get_mut(&entry_key).unwrap().cached_pte = new_pte;

            let old_present = old_pte.present();
            let new_present = new_pte.present();

            // Snapshot affected VAs with their per-VA levels before mutating.
            let va_levels: Vec<(VaKey, PageTableLevel)> = self.entries[&entry_key]
                .va_levels
                .iter()
                .map(|(&k, &v)| (k, v))
                .collect();

            for ((view, ctx), level) in va_levels {
                let va_key = (view, ctx);

                let old_leaf = old_present && is_leaf(level, old_pte);
                let new_leaf = new_present && is_leaf(level, new_pte);

                let need_teardown = old_present
                    && (!new_present || old_pte.pfn() != new_pte.pfn() || old_leaf != new_leaf);

                let need_setup = new_present
                    && (!old_present || old_pte.pfn() != new_pte.pfn() || old_leaf != new_leaf);

                if !need_teardown && !need_setup {
                    continue;
                }

                // ── Teardown old mapping ─────────────────────────────────
                if need_teardown {
                    if let Some(va) = self.vas.get(&va_key)
                        && va.paged_in
                    {
                        let pa = va.resolved_pa.unwrap();
                        events.push(PageTableMonitorEvent::PageOut(PageEntryUpdate {
                            view,
                            ctx,
                            pa,
                        }));
                        let va = self.vas.get_mut(&va_key).unwrap();
                        va.paged_in = false;
                        va.resolved_pa = None;
                    }

                    if !old_leaf {
                        self.tear_down_subtree(vmi, va_key, entry_key);
                    }
                }

                // ── Setup new mapping ────────────────────────────────────
                if need_setup {
                    if new_leaf {
                        let pa = leaf_pa(ctx.va, level, new_pte.pfn());
                        if let Some(va) = self.vas.get_mut(&va_key) {
                            va.paged_in = true;
                            va.resolved_pa = Some(pa);
                        }
                        events.push(PageTableMonitorEvent::PageIn(PageEntryUpdate {
                            view,
                            ctx,
                            pa,
                        }));
                    }
                    else {
                        self.walk_subtree(vmi, va_key, new_pte.pfn(), level, &mut events)?;
                    }
                }
            }
        }

        Ok(events)
    }
}
