//! Monitors Arm64 stage-1 descriptors using the driver's paging geometry.
//!
//! Virtual addresses, descriptors, and protected table pages have separate
//! indexes. Descriptor dependencies carry their level per address because
//! roots can share a physical table at different levels. Dirty descriptors are
//! visited in ascending level order, with each affected address rewalked only
//! once from its root to observe the final hierarchy rather than an obsolete
//! subtree.
//!
//! Callers must serialize table writes while a writer is stepped. A write on a
//! known table page marks every monitored descriptor in that view
//! conservatively. This covers interior-byte writes, pair stores, and stores
//! spanning pages without decoding instructions. Pending work remains local to
//! the writer vCPU. No page-walk-update protection option is required.

use std::collections::{HashMap, HashSet};

use vmi_arch_arm64::{Arm64, PageTableEntry, PageTableLevel, PagingGeometry};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, Pa, VcpuId, View, VmiCore, VmiError,
    driver::{VmiDriver, VmiQueryProtection, VmiRead, VmiSetProtection},
};

use super::super::{
    ArchAdapter, PageEntryUpdate, PageTableMonitorAdapter, PageTableMonitorEvent, TagType,
};

/// Identifies one address registration in a view.
type VaKey = (View, AddressContext);

/// Identifies one descriptor in a view.
type EntryKey = (View, Pa);

/// Identifies one protected table page in a view.
type TableKey = (View, Gfn);

/// Holds caller references and the last resolved walk for an address.
struct MonitoredVa<Tag> {
    /// Identifies the caller in diagnostic output.
    tag: Tag,
    /// Counts balanced monitor acquisitions for the same address and view.
    references: u32,
    /// Retains the old mapping until the replacement walk is installed.
    resolved_pa: Option<Pa>,
    /// Includes partially installed entries when a driver operation fails.
    entry_keys: Vec<EntryKey>,
}

/// Holds a descriptor snapshot and its address dependencies.
struct MonitoredEntry {
    /// Preserves the snapshot across additional address registrations.
    cached_pte: PageTableEntry,
    /// Records levels per address rather than assuming a table has one role.
    va_levels: HashMap<VaKey, PageTableLevel>,
}

/// Owns the original protection until the last descriptor is released.
struct MonitoredTable {
    /// Counts distinct monitored descriptors rather than address references.
    references: u32,
    /// Captures protection before removing write permission.
    previous_access: MemoryAccess,
}

/// Describes the translation effect of a descriptor, excluding access
/// attributes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Descriptor {
    /// Stops the walk without a physical mapping.
    Invalid,
    /// Advances the walk to a table base.
    Table(Pa),
    /// Terminates the walk at a page or legal block base.
    Leaf(Pa),
}

/// Classifies a descriptor and rejects reserved types and misaligned outputs.
fn descriptor<Geometry: PagingGeometry>(level: PageTableLevel, pte: PageTableEntry) -> Descriptor {
    let page_shift = Geometry::GRANULE.page_shift();
    // Address bits below the granule shift are reserved above the attributes.
    let reserved_address = ((1 << page_shift) - 1) & !0xfff;
    if !pte.valid() || pte.0 & reserved_address != 0 {
        return Descriptor::Invalid;
    }

    if level == PageTableLevel::L3 {
        if pte.table_or_page() {
            return Descriptor::Leaf(Pa(pte.output_address(page_shift)));
        }
        return Descriptor::Invalid;
    }

    if pte.table_or_page() {
        return Descriptor::Table(Pa(pte.output_address(page_shift)));
    }

    if pte.block() && Geometry::GRANULE.allows_block(level) {
        let shift = Geometry::control().level_shift(level);
        let reserved_address = ((1 << shift) - 1) & !((1 << page_shift) - 1);
        if pte.0 & reserved_address == 0 {
            return Descriptor::Leaf(Pa(pte.output_address(shift)));
        }
    }

    Descriptor::Invalid
}

/// Represents a freshly read walk that has not acquired protection references.
struct Walk {
    /// Lists descriptors in root-to-leaf order.
    entries: Vec<(EntryKey, PageTableLevel, PageTableEntry)>,
    /// Records the final physical address, including its byte offset.
    resolved_pa: Option<Pa>,
}

impl<Driver, Tag, Geometry> ArchAdapter<Driver, Tag> for Arm64<Geometry>
where
    Driver:
        VmiDriver<Architecture = Arm64<Geometry>> + VmiRead + VmiQueryProtection + VmiSetProtection,
    Tag: TagType,
    Geometry: PagingGeometry,
{
    type Monitor = PageTableMonitorArm64<Tag, Geometry>;
}

/// Tracks Arm64 mappings with the geometry selected by the driver.
pub struct PageTableMonitorArm64<Tag, Geometry>
where
    Tag: TagType,
    Geometry: PagingGeometry,
{
    /// Holds balanced address registrations.
    vas: HashMap<VaKey, MonitoredVa<Tag>>,
    /// Shares descriptor ownership across address registrations.
    entries: HashMap<EntryKey, MonitoredEntry>,
    /// Shares table protection across distinct descriptors.
    tables: HashMap<TableKey, MonitoredTable>,
    /// Isolates committed writes by the vCPU that will finish its step.
    dirty: HashMap<VcpuId, HashSet<EntryKey>>,
    /// Pins frame size and walk geometry without runtime storage.
    _geometry: std::marker::PhantomData<Geometry>,
}

impl<Tag, Geometry> PageTableMonitorArm64<Tag, Geometry>
where
    Tag: TagType,
    Geometry: PagingGeometry,
{
    /// Reads the reachable hierarchy without altering reference ownership.
    fn read_walk<Driver>(vmi: &VmiCore<Driver>, (view, ctx): VaKey) -> Result<Walk, VmiError>
    where
        Driver: VmiRead<Architecture = Arm64<Geometry>>,
    {
        let control = Geometry::control();
        let mut table = ctx.root;
        let mut level = control.start_level();
        let mut entries = Vec::with_capacity(4);
        let resolved_pa = loop {
            let offset = Arm64::<Geometry>::pa_offset(table) + control.index(ctx.va, level) * 8;
            if table.0 & 7 != 0 || offset + 8 > Arm64::<Geometry>::PAGE_SIZE {
                return Err(VmiError::OutOfBounds);
            }
            let entry_pa = table + control.index(ctx.va, level) * 8;
            let _ = vmi.flush_gfn_cache_entry(Arm64::<Geometry>::gfn_from_pa(entry_pa));
            let pte = vmi.read_struct::<PageTableEntry>(entry_pa)?;
            entries.push(((view, entry_pa), level, pte));
            match descriptor::<Geometry>(level, pte) {
                Descriptor::Invalid => break None,
                Descriptor::Leaf(base) => break Some(base + control.offset(ctx.va, level)),
                Descriptor::Table(base) => {
                    table = base;
                    level = match level.next() {
                        Some(level) => level,
                        None => break None,
                    };
                }
            }
        };
        Ok(Walk {
            entries,
            resolved_pa,
        })
    }

    /// Acquires a distinct descriptor reference and protects its table page.
    fn attach_entry<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        va_key: VaKey,
        entry_key: EntryKey,
        level: PageTableLevel,
        pte: PageTableEntry,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiQueryProtection + VmiSetProtection,
    {
        if let Some(entry) = self.entries.get_mut(&entry_key) {
            entry.va_levels.insert(va_key, level);
            return Ok(());
        }

        let (view, pa) = entry_key;
        let table_key = (view, Arm64::<Geometry>::gfn_from_pa(pa));
        if let Some(table) = self.tables.get_mut(&table_key) {
            table.references = table
                .references
                .checked_add(1)
                .expect("table reference overflow");
        }
        else {
            let previous_access = vmi.memory_access(table_key.1, view)?;
            vmi.set_memory_access(table_key.1, view, previous_access & !MemoryAccess::W)?;
            self.tables.insert(
                table_key,
                MonitoredTable {
                    references: 1,
                    previous_access,
                },
            );
        }

        self.entries.insert(
            entry_key,
            MonitoredEntry {
                cached_pte: pte,
                va_levels: HashMap::from([(va_key, level)]),
            },
        );
        Ok(())
    }

    /// Releases an address dependency, retaining ownership if restoration
    /// fails.
    fn detach_entry<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        va_key: VaKey,
        entry_key: EntryKey,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiQueryProtection + VmiSetProtection,
    {
        let entry = match self.entries.get(&entry_key) {
            Some(entry) => entry,
            None => return Ok(()),
        };
        if !entry.va_levels.contains_key(&va_key) {
            return Ok(());
        }
        if entry.va_levels.len() > 1 {
            self.entries
                .get_mut(&entry_key)
                .expect("monitored descriptor")
                .va_levels
                .remove(&va_key);
            return Ok(());
        }

        let (view, pa) = entry_key;
        let table_key = (view, Arm64::<Geometry>::gfn_from_pa(pa));
        let table = self.tables.get(&table_key).expect("protected table");
        if table.references == 1 {
            match vmi.set_memory_access(table_key.1, view, table.previous_access) {
                Ok(()) => {}
                Err(VmiError::ViewNotFound) => {}
                Err(err) => return Err(err),
            }
            self.tables.remove(&table_key);
        }
        else {
            self.tables
                .get_mut(&table_key)
                .expect("protected table")
                .references -= 1;
        }
        self.entries.remove(&entry_key);
        for dirty in self.dirty.values_mut() {
            dirty.remove(&entry_key);
        }
        Ok(())
    }

    /// Installs a replacement walk while retaining all failed cleanup for
    /// retry.
    fn install_walk<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        va_key: VaKey,
        walk: Walk,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiQueryProtection + VmiSetProtection,
    {
        for &(entry_key, level, pte) in &walk.entries {
            self.attach_entry(vmi, va_key, entry_key, level, pte)?;
            let va = self.vas.get_mut(&va_key).expect("monitored address");
            if !va.entry_keys.contains(&entry_key) {
                va.entry_keys.push(entry_key);
            }
        }

        let old_keys = self.vas[&va_key].entry_keys.clone();
        for entry_key in old_keys {
            if !walk.entries.iter().any(|&(key, _, _)| key == entry_key) {
                self.detach_entry(vmi, va_key, entry_key)?;
                self.vas
                    .get_mut(&va_key)
                    .expect("monitored address")
                    .entry_keys
                    .retain(|&key| key != entry_key);
            }
        }

        let va = self.vas.get_mut(&va_key).expect("monitored address");
        va.entry_keys = walk.entries.into_iter().map(|(key, _, _)| key).collect();
        va.resolved_pa = walk.resolved_pa;
        Ok(())
    }

    /// Releases one caller reference or every reference when forced.
    fn unmonitor_internal<Driver>(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: AddressContext,
        view: View,
        force: bool,
    ) -> Result<(), VmiError>
    where
        Driver: VmiRead + VmiQueryProtection + VmiSetProtection,
    {
        let va_key = (view, ctx);
        let va = match self.vas.get_mut(&va_key) {
            Some(va) => va,
            None => return Ok(()),
        };
        if !force && va.references > 1 {
            va.references -= 1;
            return Ok(());
        }

        let entry_keys = va.entry_keys.clone();
        for entry_key in entry_keys.into_iter().rev() {
            self.detach_entry(vmi, va_key, entry_key)?;
            self.vas
                .get_mut(&va_key)
                .expect("monitored address")
                .entry_keys
                .retain(|&key| key != entry_key);
        }
        self.vas.remove(&va_key);
        Ok(())
    }
}

impl<Driver, Tag, Geometry> PageTableMonitorAdapter<Driver, Tag>
    for PageTableMonitorArm64<Tag, Geometry>
where
    Driver:
        VmiDriver<Architecture = Arm64<Geometry>> + VmiRead + VmiQueryProtection + VmiSetProtection,
    Tag: TagType,
    Geometry: PagingGeometry,
{
    /// Creates empty ownership and per-vCPU dirty indexes.
    fn new() -> Self {
        Self {
            vas: HashMap::new(),
            entries: HashMap::new(),
            tables: HashMap::new(),
            dirty: HashMap::new(),
            _geometry: std::marker::PhantomData,
        }
    }

    /// Returns the number of pages whose original protection is owned.
    fn monitored_tables(&self) -> usize {
        self.tables.len()
    }

    /// Returns the number of distinct descriptor dependencies.
    fn monitored_entries(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of registrations with a resolved physical address.
    fn paged_in_entries(&self) -> usize {
        self.vas
            .values()
            .filter(|va| va.resolved_pa.is_some())
            .count()
    }

    /// Logs registrations and ownership counts.
    fn dump(&self) {
        tracing::trace!(
            tables = self.tables.len(),
            entries = self.entries.len(),
            "Arm64 monitor state"
        );
        for (&(view, ctx), va) in &self.vas {
            tracing::trace!(%view, va = %ctx.va, root = %ctx.root, tag = ?va.tag,
                references = va.references, resolved_pa = ?va.resolved_pa, "monitored address");
        }
    }

    /// Acquires a balanced registration without overwriting shared snapshots.
    fn monitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
        tag: Tag,
    ) -> Result<(), VmiError> {
        let va_key = (view, ctx.into());
        if let Some(va) = self.vas.get_mut(&va_key) {
            va.references = va
                .references
                .checked_add(1)
                .expect("address reference overflow");
            return Ok(());
        }
        let walk = Self::read_walk(vmi, va_key)?;
        self.vas.insert(
            va_key,
            MonitoredVa {
                tag,
                references: 1,
                resolved_pa: None,
                entry_keys: Vec::with_capacity(4),
            },
        );
        match self.install_walk(vmi, va_key, walk) {
            Ok(()) => Ok(()),
            Err(err) => {
                if let Err(err) = self.unmonitor_internal(vmi, va_key.1, view, true) {
                    tracing::warn!(%err, "retaining failed monitor cleanup for retry");
                }
                Err(err)
            }
        }
    }

    /// Releases one registration reference and propagates restoration failures.
    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError> {
        self.unmonitor_internal(vmi, ctx.into(), view, false)
    }

    /// Releases every reference while preserving failed cleanup for retry.
    fn unmonitor_by_force(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError> {
        self.unmonitor_internal(vmi, ctx.into(), view, true)
    }

    /// Releases all registrations, retaining and logging restoration failures.
    fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>) {
        let va_keys = self.vas.keys().copied().collect::<Vec<_>>();
        for (view, ctx) in va_keys {
            if let Err(err) = self.unmonitor_internal(vmi, ctx, view, true) {
                tracing::warn!(%err, %view, "failed to release table protection");
            }
        }
        if self.vas.is_empty() {
            self.dirty.clear();
        }
    }

    /// Releases a view's registrations without affecting other views.
    fn unmonitor_view(&mut self, vmi: &VmiCore<Driver>, view: View) {
        let contexts = self
            .vas
            .keys()
            .filter(|&&(key_view, _)| key_view == view)
            .map(|&(_, ctx)| ctx)
            .collect::<Vec<_>>();
        for ctx in contexts {
            if let Err(err) = self.unmonitor_internal(vmi, ctx, view, true) {
                tracing::warn!(%err, %view, "failed to release table protection");
            }
        }
    }

    /// Marks all descriptors in a view when a known table page is written.
    fn mark_dirty_entry(&mut self, entry_pa: Pa, view: View, vcpu_id: VcpuId) -> bool {
        let gfn = Arm64::<Geometry>::gfn_from_pa(entry_pa);
        if !self.tables.contains_key(&(view, gfn)) {
            return false;
        }
        let dirty = self.dirty.entry(vcpu_id).or_default();
        dirty.extend(
            self.entries
                .keys()
                .filter(|&&(key_view, _)| key_view == view)
                .copied(),
        );
        true
    }

    /// Rewalks changed dependencies parent-first and emits old-out before
    /// new-in.
    fn process_dirty_entries(
        &mut self,
        vmi: &VmiCore<Driver>,
        vcpu_id: VcpuId,
    ) -> Result<Vec<PageTableMonitorEvent>, VmiError> {
        let dirty_keys = self.dirty.remove(&vcpu_id).unwrap_or_default();
        let mut to_process = dirty_keys
            .iter()
            .filter_map(|&key| {
                self.entries.get(&key).and_then(|entry| {
                    entry
                        .va_levels
                        .values()
                        .copied()
                        .min()
                        .map(|level| (level, key))
                })
            })
            .collect::<Vec<_>>();
        to_process.sort_by_key(|&(level, (view, pa))| (level, view.0, pa.0));
        let mut processed = HashSet::new();
        let mut events = Vec::new();

        let result = (|| -> Result<(), VmiError> {
            for (_, entry_key) in to_process {
                let entry = match self.entries.get(&entry_key) {
                    Some(entry) => entry,
                    None => continue,
                };
                let _ = vmi.flush_gfn_cache_entry(Arm64::<Geometry>::gfn_from_pa(entry_key.1));
                let new_pte = vmi.read_struct::<PageTableEntry>(entry_key.1)?;
                if entry.cached_pte == new_pte {
                    continue;
                }
                let mut va_keys = entry.va_levels.keys().copied().collect::<Vec<_>>();
                va_keys.sort_by_key(|&(view, ctx)| (view.0, ctx.root.0, ctx.va.0));
                for va_key in va_keys {
                    if !processed.insert(va_key) {
                        continue;
                    }
                    let old_pa = self.vas[&va_key].resolved_pa;
                    let walk = Self::read_walk(vmi, va_key)?;
                    let new_pa = walk.resolved_pa;
                    let old_keys = &self.vas[&va_key].entry_keys;
                    let chain_changed = old_keys.len() != walk.entries.len()
                        || old_keys
                            .iter()
                            .zip(&walk.entries)
                            .any(|(old_key, (new_key, _, _))| old_key != new_key);
                    self.install_walk(vmi, va_key, walk)?;
                    if old_pa != new_pa || chain_changed {
                        let (view, ctx) = va_key;
                        if let Some(pa) = old_pa {
                            events.push(PageTableMonitorEvent::PageOut(PageEntryUpdate {
                                view,
                                ctx,
                                pa,
                            }));
                        }
                        if let Some(pa) = new_pa {
                            events.push(PageTableMonitorEvent::PageIn(PageEntryUpdate {
                                view,
                                ctx,
                                pa,
                            }));
                        }
                    }
                }
                if let Some(entry) = self.entries.get_mut(&entry_key) {
                    entry.cached_pte = new_pte;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(events),
            Err(err) => {
                self.dirty.entry(vcpu_id).or_default().extend(dirty_keys);
                Err(err)
            }
        }
    }
}
