//! Page table monitor for the AMD64 architecture.
use std::collections::{HashMap, HashSet};

use vmi_arch_amd64::{Amd64, PageTableEntry, PageTableLevel};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, Pa, VcpuId, View, VmiCore, VmiDriver,
    VmiError,
};

use super::{
    super::{PageEntryUpdate, PageTableMonitorEvent, TagType},
    ArchAdapter, PageTableMonitorArchAdapter,
};

#[derive(Debug, Clone, Copy)]
struct MonitoredPageTableOffset<Tag>
where
    Tag: TagType,
{
    offset: u16,
    #[expect(dead_code)]
    tag: Tag,
}

#[derive(Debug)]
struct MonitoredPageTable<Tag>
where
    Tag: TagType,
{
    vas: HashMap<AddressContext, MonitoredPageTableOffset<Tag>>,
}

impl<Tag> Default for MonitoredPageTable<Tag>
where
    Tag: TagType,
{
    fn default() -> Self {
        Self {
            vas: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MonitoredPageTableLevel<Tag>
where
    Tag: TagType,
{
    level: PageTableLevel,
    tag: Tag,
}

#[derive(Debug)]
struct MonitoredPageTableEntry<Tag>
where
    Tag: TagType,
{
    value: PageTableEntry,
    vas: HashMap<AddressContext, MonitoredPageTableLevel<Tag>>,
}

impl<Tag> Default for MonitoredPageTableEntry<Tag>
where
    Tag: TagType,
{
    fn default() -> Self {
        Self {
            value: PageTableEntry::default(),
            vas: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct PagedInEntry<Tag>
where
    Tag: TagType,
{
    pa: Pa,
    tag: Tag,
}

struct PageTableController<Driver>
where
    Driver: VmiDriver,
{
    monitored_gfns: HashSet<(View, Gfn)>,
    _marker: std::marker::PhantomData<Driver>,
}

impl<Driver> PageTableController<Driver>
where
    Driver: VmiDriver,
{
    fn new() -> Self {
        Self {
            monitored_gfns: HashSet::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Read a page table entry from the guest physical address.
    fn read_page_table_entry(
        &self,
        vmi: &VmiCore<Driver>,
        pa: Pa,
    ) -> Result<PageTableEntry, VmiError> {
        vmi.read_struct(pa)
    }

    /// Monitor a guest frame number for write access.
    fn monitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        self.monitored_gfns.insert((view, gfn));
        vmi.set_memory_access(gfn, view, MemoryAccess::R)
    }

    /// Unmonitor a guest frame number.
    fn unmonitor(&mut self, vmi: &VmiCore<Driver>, gfn: Gfn, view: View) -> Result<(), VmiError> {
        let gfn_was_present = self.monitored_gfns.remove(&(view, gfn));
        debug_assert!(
            gfn_was_present,
            "trying to unmonitor an unmonitored (gfn, view)"
        );

        match vmi.set_memory_access(gfn, view, MemoryAccess::RW) {
            Ok(()) => Ok(()),
            Err(VmiError::ViewNotFound) => {
                //
                // The view was not found. This can happen if the view was
                // destroyed before unmonitoring.
                //
                tracing::warn!(%gfn, %view, "view not found");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Unmonitor all monitored guest frame numbers.
    fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>) {
        for &(view, gfn) in &self.monitored_gfns {
            let _ = vmi.set_memory_access(gfn, view, MemoryAccess::RW);
        }

        self.monitored_gfns.clear();
    }
}

impl<Driver, Tag> ArchAdapter<Driver, Tag> for Amd64
where
    Driver: VmiDriver<Architecture = Amd64>,
    Tag: TagType,
{
    type Impl = PageTableMonitorAmd64<Driver, Tag>;
}

/// A page table monitor for the AMD64 architecture.
pub struct PageTableMonitorAmd64<Driver, Tag>
where
    Driver: VmiDriver<Architecture = Amd64>,
    Tag: TagType,
{
    controller: PageTableController<Driver>,

    /// Monitored page tables.
    /// Each GFN is monitored for write access.
    tables: HashMap<(View, Gfn), MonitoredPageTable<Tag>>,

    /// Monitored page table entries.
    /// Each PA is monitored for write access.
    entries: HashMap<(View, Pa), MonitoredPageTableEntry<Tag>>,

    /// Paged-in entries.
    /// VAs that are currently resolved to a PAs.
    paged_in: HashMap<(View, AddressContext), PagedInEntry<Tag>>,

    /// Dirty page tables.
    /// Addresses of page table entries that have been modified.
    dirty: HashMap<VcpuId, HashSet<(View, Pa)>>,
}

impl<Driver, Tag> PageTableMonitorArchAdapter<Driver, Tag> for PageTableMonitorAmd64<Driver, Tag>
where
    Driver: VmiDriver<Architecture = Amd64>,
    Tag: TagType,
{
    fn new() -> Self {
        Self {
            controller: PageTableController::new(),
            tables: HashMap::new(),
            entries: HashMap::new(),
            paged_in: HashMap::new(),
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
        self.paged_in.len()
    }

    fn dump(&self) {
        println!("==================== <DUMP> ====================");
        let mut tables = self.tables.iter().collect::<Vec<_>>();
        tables.sort_by_key(|&(&(_view, gfn), _)| gfn);

        let mut entries_remaining = self.entries.keys().collect::<HashSet<_>>();

        for (&(view_table, gfn), table) in tables {
            println!("Table {:#x?}", gfn);

            let mut entries = self
                .entries
                .iter()
                .filter(|&(&(view_entry, pa), _)| {
                    Amd64::gfn_from_pa(pa) == gfn && view_table == view_entry
                })
                .collect::<Vec<_>>();
            entries.sort_by_key(|&(&(view, pa), _)| (Amd64::pa_offset(pa), view));

            let mut vas_in_table = HashSet::new();
            let mut vas_in_entries = HashSet::new();

            for (&(view_entry, pa), entry) in entries {
                println!(
                    "  Entry {:#x?} (view: {})",
                    Amd64::pa_offset(pa),
                    view_entry,
                );

                let mut vas = entry.vas.iter().collect::<Vec<_>>();
                vas.sort_by_key(|&(&ctx, _)| (ctx.va, ctx.root));

                for (&ctx, &MonitoredPageTableLevel { level, tag }) in vas {
                    println!(
                        "    VA: {:#x?}, Root: {:#x?}, Level: {:?}, Tag: {:?}",
                        ctx.va, ctx.root, level, tag
                    );

                    vas_in_entries.insert(ctx);
                }

                entries_remaining.remove(&(view_entry, pa));
            }

            for &ctx in table.vas.keys() {
                vas_in_table.insert(ctx);
            }

            if vas_in_entries != vas_in_table {
                println!("  --- xxx MISMATCH xxx ---");
                println!("  VAs in entries: {:#x?}", vas_in_entries);
                println!("  VAs in table  : {:#x?}", vas_in_table);
            }
        }

        if !entries_remaining.is_empty() {
            println!("--- xxx MISMATCH xxx ---");
            println!("PAs in entries remaining: {:#x?}", entries_remaining);
        }
        println!("==================== </DUMP> ====================");
    }

    fn monitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
        tag: Tag,
    ) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let gfn = Amd64::gfn_from_pa(ctx.root);
        self.monitor_entry(vmi, ctx, view, tag, gfn, PageTableLevel::Pml4)?;

        Ok(())
    }

    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError> {
        let ctx = ctx.into();
        let gfn = Amd64::gfn_from_pa(ctx.root);

        let mut orphaned = HashSet::new();
        self.unmonitor_entry(vmi, ctx, view, gfn, PageTableLevel::Pml4, &mut orphaned)?;

        for pa in orphaned {
            self.entries.remove(&(view, pa));
        }

        Ok(())
    }

    fn unmonitor_view(&mut self, _vmi: &VmiCore<Driver>, _view: View) {
        unimplemented!("unmonitor view not implemented");
    }

    fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>) {
        self.controller.unmonitor_all(vmi);
        self.tables.clear();
        self.entries.clear();
        self.dirty.clear();
    }

    fn mark_dirty_entry(&mut self, entry_pa: Pa, view: View, vcpu_id: VcpuId) -> bool {
        if !self.entries.contains_key(&(view, entry_pa)) {
            //tracing::trace!(
            //    %entry_pa, %view, %vcpu_id, found = false,
            //    "marking dirty page table entry"
            //);
            return false;
        }

        tracing::trace!(
            %entry_pa, %view, %vcpu_id, found = true,
            "marking dirty page table entry"
        );

        self.dirty
            .entry(vcpu_id)
            .or_default()
            .insert((view, entry_pa))
    }

    fn process_dirty_entries(
        &mut self,
        vmi: &VmiCore<Driver>,
        vcpu_id: VcpuId,
    ) -> Result<Vec<PageTableMonitorEvent>, VmiError> {
        let dirty = match self.dirty.remove(&vcpu_id) {
            Some(dirty) => dirty,
            None => {
                tracing::trace!(%vcpu_id, "no dirty entries");
                return Ok(Vec::new());
            }
        };

        let mut result = Vec::new();

        for (view, entry_pa) in dirty {
            if let Some(resolved) = self.update_entry(vmi, entry_pa, view)? {
                result.extend(resolved);
            }
        }

        Ok(result)
    }
}

impl<Driver, Tag> PageTableMonitorAmd64<Driver, Tag>
where
    Driver: VmiDriver<Architecture = Amd64>,
    Tag: TagType,
{
    fn update_entry(
        &mut self,
        vmi: &VmiCore<Driver>,
        entry_pa: Pa,
        view: View,
    ) -> Result<Option<Vec<PageTableMonitorEvent>>, VmiError> {
        let entry = match self.entries.get_mut(&(view, entry_pa)) {
            Some(entry) => entry,
            None => {
                //tracing::trace!(
                //    %entry_pa, %view, found = false,
                //    "update page table entry"
                //);
                return Ok(None);
            }
        };

        let old_value = entry.value;
        let new_value = self.controller.read_page_table_entry(vmi, entry_pa)?;

        //tracing::trace!(
        //    %entry_pa, %view, found = true,
        //    same = old_value == new_value,
        //    old_present = old_value.present(),
        //    new_present = new_value.present(),
        //    old_large = old_value.large(),
        //    new_large = new_value.large(),
        //    old_pfn = %old_value.pfn(),
        //    new_pfn = %new_value.pfn(),
        //    "update page table entry"
        //);

        if old_value == new_value {
            return Ok(None);
        }

        entry.value = new_value;

        if old_value.present() && new_value.present() && old_value.pfn() != new_value.pfn() {
            self.dump();
            unimplemented!(
                "PFN change not implemented, entry PA: {:?} old: {:#x?} (PFN: {}), new: {:#x?} (PFN: {})",
                entry_pa, old_value, old_value.pfn(), new_value, new_value.pfn()
            );
        }
        else if old_value.present() && !new_value.present() {
            if old_value.large() {
                self.dump();
                unimplemented!("large page page-out not implemented");
            }
            else {
                let vas = entry.vas.clone();
                return self.page_out(vmi, entry_pa, vas, old_value, view);
            }
        }
        else if !old_value.present() && new_value.present() {
            if new_value.large() {
                self.dump();
                unimplemented!("large page page-in not implemented");
            }
            else {
                let vas = entry.vas.clone();
                return self.page_in(vmi, entry_pa, vas, new_value, view);
            }
        }

        Ok(None)
    }

    fn page_in(
        &mut self,
        vmi: &VmiCore<Driver>,
        entry_pa: Pa,
        entry_vas: HashMap<AddressContext, MonitoredPageTableLevel<Tag>>,
        new_value: PageTableEntry,
        view: View,
    ) -> Result<Option<Vec<PageTableMonitorEvent>>, VmiError> {
        let mut result = Vec::new();

        for (ctx, MonitoredPageTableLevel { level, tag }) in entry_vas {
            let index = Amd64::va_index_for(ctx.va, level) * 8;
            debug_assert_eq!(index, Amd64::pa_offset(entry_pa));

            match level.next() {
                Some(next_level) => {
                    // If this is a page-in at a higher level than the PT (e.g., PML4, PDPT, PD),
                    // we need to monitor the next level. If the monitor_entry function returns
                    // an update, it means that the whole chain of page tables has been resolved.
                    // In that case, we add the update to the result.
                    if let Some(pa) =
                        self.monitor_entry(vmi, ctx, view, tag, new_value.pfn(), next_level)?
                    {
                        let update = PageEntryUpdate { view, ctx, pa };
                        result.push(PageTableMonitorEvent::PageIn(update));
                    }
                }

                None => {
                    debug_assert_eq!(level, PageTableLevel::Pt);

                    let pa = Amd64::pa_from_gfn(new_value.pfn()) + Amd64::va_offset(ctx.va);

                    tracing::debug!(
                        %view,
                        va = %ctx.va,
                        root = %ctx.root,
                        %pa,
                        ?tag,
                        "page-in event"
                    );

                    debug_assert!(!self.paged_in.contains_key(&(view, ctx)));
                    self.paged_in.insert((view, ctx), PagedInEntry { pa, tag });

                    let update = PageEntryUpdate { view, ctx, pa };
                    result.push(PageTableMonitorEvent::PageIn(update));
                }
            }
        }

        Ok(Some(result))
    }

    fn page_out(
        &mut self,
        vmi: &VmiCore<Driver>,
        entry_pa: Pa,
        entry_vas: HashMap<AddressContext, MonitoredPageTableLevel<Tag>>,
        old_value: PageTableEntry,
        view: View,
    ) -> Result<Option<Vec<PageTableMonitorEvent>>, VmiError> {
        let mut result = Vec::new();
        let mut orphaned = HashSet::new();

        for (ctx, MonitoredPageTableLevel { level, .. }) in entry_vas {
            let index = Amd64::va_index_for(ctx.va, level) * 8;
            debug_assert_eq!(index, Amd64::pa_offset(entry_pa));

            if let Some(paged_in_entry) = self.paged_in.remove(&(view, ctx)) {
                let PagedInEntry { pa, tag } = paged_in_entry;

                tracing::debug!(
                    %view,
                    va = %ctx.va,
                    root = %ctx.root,
                    %pa,
                    ?tag,
                    "page-out event"
                );

                let update = PageEntryUpdate { view, ctx, pa };
                result.push(PageTableMonitorEvent::PageOut(update));
            }

            if let Some(next_level) = level.next() {
                self.unmonitor_entry(vmi, ctx, view, old_value.pfn(), next_level, &mut orphaned)?;
            }
        }

        for pa in orphaned {
            self.entries.remove(&(view, pa));
        }

        Ok(Some(result))
    }

    /// Recursively monitor a page table entry.
    ///
    /// Returns the resolved PA if the entry is already paged-in.
    fn monitor_entry(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: AddressContext,
        view: View,
        tag: Tag,
        table_gfn: Gfn,
        level: PageTableLevel,
    ) -> Result<Option<Pa>, VmiError> {
        let table = self.tables.entry((view, table_gfn)).or_default();

        // Monitor the table if this is the first VA in it.
        if table.vas.is_empty() {
            self.controller.monitor(vmi, table_gfn, view)?;
        }

        let offset = (Amd64::va_index_for(ctx.va, level) * 8) as u16;
        let previous = table
            .vas
            .insert(ctx, MonitoredPageTableOffset { offset, tag });
        debug_assert!(match previous {
            Some(previous) => previous.offset == offset,
            None => true,
        });

        let entry_pa = Amd64::pa_from_gfn(table_gfn) + Amd64::va_index_for(ctx.va, level) * 8;

        let entry = self.entries.entry((view, entry_pa)).or_default();
        entry.value = self.controller.read_page_table_entry(vmi, entry_pa)?;
        let previous = entry
            .vas
            .insert(ctx, MonitoredPageTableLevel { level, tag });
        debug_assert!(match previous {
            Some(previous) => previous.level == level,
            None => true,
        });

        // If the entry is not present, there is no need to monitor the next
        // level.
        if !entry.value.present() {
            return Ok(None);
        }

        let next_level = match level.next() {
            Some(next_level) => next_level,
            None => {
                debug_assert_eq!(level, PageTableLevel::Pt);

                let pa = Amd64::pa_from_gfn(entry.value.pfn()) + Amd64::va_offset(ctx.va);

                self.paged_in.insert((view, ctx), PagedInEntry { pa, tag });

                tracing::debug!(
                    %view,
                    va = %ctx.va,
                    root = %ctx.root,
                    %pa,
                    "monitoring already paged-in entry"
                );

                return Ok(Some(pa));
            }
        };

        let next_table_gfn = entry.value.pfn();
        self.monitor_entry(vmi, ctx, view, tag, next_table_gfn, next_level)
    }

    /// Recursively unmonitor a page table entry.
    ///
    /// Returns the resolved PA if the entry is paged-in.
    fn unmonitor_entry(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: AddressContext,
        view: View,
        table_gfn: Gfn,
        level: PageTableLevel,
        orphaned: &mut HashSet<Pa>,
    ) -> Result<Option<Pa>, VmiError> {
        self.paged_in.remove(&(view, ctx));

        let table = match self.tables.get_mut(&(view, table_gfn)) {
            Some(table) => table,
            None => {
                //
                // Allow unmonitoring a root table that was not monitored.
                //

                if level == PageTableLevel::Pml4 {
                    return Ok(None);
                }

                tracing::error!(%view, %table_gfn, "Table not found");
                panic!("table not found");
            }
        };

        let MonitoredPageTableOffset { offset, .. } = match table.vas.remove(&ctx) {
            Some(offset) => offset,
            None => {
                if level == PageTableLevel::Pml4 {
                    return Ok(None);
                }

                tracing::error!(%view, %table_gfn, va = %ctx.va, "VA not found in table");
                panic!("VA not found");
            }
        };

        debug_assert_eq!(offset, (Amd64::va_index_for(ctx.va, level) * 8) as u16);

        if table.vas.is_empty() {
            self.controller.unmonitor(vmi, table_gfn, view)?;
            self.tables.remove(&(view, table_gfn));
        }

        let entry_pa = Amd64::pa_from_gfn(table_gfn) + offset as u64;

        let entry = match self.entries.get_mut(&(view, entry_pa)) {
            Some(entry) => entry,
            None => {
                tracing::error!(%view, %entry_pa, "Child entry not found");
                debug_assert!(false, "child entry not found");
                return Ok(None);
            }
        };

        if !entry.value.present() {
            tracing::debug!(%view, %entry_pa, "child entry is not present, unmonitoring");
            orphaned.insert(entry_pa);
            return Ok(None);
        }

        let MonitoredPageTableLevel { level: level2, .. } = match entry.vas.remove(&ctx) {
            Some(next_level) => next_level,
            None => {
                tracing::error!(%view, %entry_pa, va = %ctx.va, "Child entry not found");
                panic!("child entry not found");
            }
        };

        if entry.vas.is_empty() {
            tracing::debug!(%view, %entry_pa, "no more VAs for child entry, unmonitoring");
            orphaned.insert(entry_pa);
        }

        debug_assert_eq!(level, level2);

        let next_level = match level.next() {
            Some(next_level) => next_level,
            None => {
                debug_assert_eq!(level, PageTableLevel::Pt);

                let pa = Amd64::pa_from_gfn(entry.value.pfn()) + Amd64::va_offset(ctx.va);

                tracing::debug!(
                    %view,
                    va = %ctx.va,
                    root = %ctx.root,
                    %pa,
                    "unmonitoring paged-in entry"
                );

                return Ok(Some(pa));
            }
        };

        let next_table_gfn = entry.value.pfn();
        self.unmonitor_entry(vmi, ctx, view, next_table_gfn, next_level, orphaned)
    }
}
