//! Exercises geometry-aware monitoring through the architecture-independent
//! API.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use vmi_arch_arm64::{Arm64, Granule4KVa48, Granule16KVa47, PageTableLevel, PagingGeometry};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId,
    View, VmiCore, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryProtection, VmiRead, VmiSetProtection},
};

use super::super::{PageTableMonitor, PageTableMonitorEvent};

/// Selects the primary test view.
const VIEW: View = View(0);

/// Selects the writer whose completed step is processed.
const VCPU: VcpuId = VcpuId(0);

/// Stores guest pages and independent per-view protection for either geometry.
struct MockDriver<Geometry> {
    /// Contains little-endian guest descriptors.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,
    /// Tracks externally visible protection changes.
    access: RefCell<HashMap<(View, Gfn), MemoryAccess>>,
    /// Fails the next protection change without mutating its state.
    fail_protection: Cell<bool>,
    /// Fails reads of one selected frame.
    fail_read: Cell<Option<Gfn>>,
    /// Selects the architecture's frame size.
    _geometry: std::marker::PhantomData<Geometry>,
}

impl<Geometry: PagingGeometry> MockDriver<Geometry> {
    /// Creates an empty physical address space.
    fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            access: RefCell::new(HashMap::new()),
            fail_protection: Cell::new(false),
            fail_read: Cell::new(None),
            _geometry: std::marker::PhantomData,
        }
    }

    /// Writes bytes across frame boundaries as one guest store.
    fn write_bytes(&self, pa: Pa, bytes: &[u8]) {
        let mut pages = self.pages.borrow_mut();
        for (index, byte) in bytes.iter().enumerate() {
            let pa = pa + index as u64;
            let gfn = Arm64::<Geometry>::gfn_from_pa(pa);
            let page = pages
                .entry(gfn)
                .or_insert_with(|| vec![0; Arm64::<Geometry>::PAGE_SIZE as usize]);
            page[Arm64::<Geometry>::pa_offset(pa) as usize] = *byte;
        }
    }

    /// Writes a descriptor without changing protection.
    fn write_descriptor(&self, pa: Pa, value: u64) {
        self.write_bytes(pa, &value.to_le_bytes());
    }

    /// Returns the current protection, defaulting to full access.
    fn access(&self, gfn: Gfn, view: View) -> MemoryAccess {
        self.access
            .borrow()
            .get(&(view, gfn))
            .copied()
            .unwrap_or(MemoryAccess::RWX)
    }

    /// Seeds protection before ownership is acquired.
    fn seed_access(&self, gfn: Gfn, view: View, access: MemoryAccess) {
        self.access.borrow_mut().insert((view, gfn), access);
    }
}

impl<Geometry: PagingGeometry> VmiDriver for MockDriver<Geometry> {
    type Architecture = Arm64<Geometry>;

    /// Returns the selected geometry's frame size.
    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: Arm64::<Geometry>::PAGE_SIZE,
            page_shift: Arm64::<Geometry>::PAGE_SHIFT,
            max_gfn: Gfn(0x100000),
            vcpus: 2,
        })
    }
}

impl<Geometry: PagingGeometry> VmiRead for MockDriver<Geometry> {
    /// Returns a snapshot of a crafted physical page.
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        if self.fail_read.get() == Some(gfn) {
            return Err(VmiError::OutOfBounds);
        }
        let page = self
            .pages
            .borrow()
            .get(&gfn)
            .cloned()
            .unwrap_or_else(|| vec![0; Arm64::<Geometry>::PAGE_SIZE as usize]);
        Ok(VmiMappedPage::new(page))
    }
}

impl<Geometry: PagingGeometry> VmiQueryProtection for MockDriver<Geometry> {
    /// Returns independently seeded protection for the requested view.
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.access(gfn, view))
    }

    /// Returns protection without architecture-specific options.
    fn memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
    ) -> Result<(MemoryAccess, MemoryAccessOptions), VmiError> {
        Ok((self.access(gfn, view), MemoryAccessOptions::empty()))
    }
}

impl<Geometry: PagingGeometry> VmiSetProtection for MockDriver<Geometry> {
    /// Mutates protection or injects a recoverable driver failure.
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        if self.fail_protection.replace(false) {
            return Err(VmiError::OutOfBounds);
        }
        self.access.borrow_mut().insert((view, gfn), access);
        Ok(())
    }

    /// Rejects unsupported options so tests exercise ordinary write protection.
    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        assert!(options.is_empty());
        self.set_memory_access(gfn, view, access)
    }
}

/// Creates a core that rereads guest pages after simulated writes.
fn core<Geometry: PagingGeometry>(
    driver: MockDriver<Geometry>,
) -> Result<VmiCore<MockDriver<Geometry>>, VmiError> {
    let mut vmi = VmiCore::new(driver)?;
    vmi.disable_gfn_cache();
    Ok(vmi)
}

/// Returns a geometry-sized frame's physical base.
fn frame<Geometry: PagingGeometry>(gfn: u64) -> Pa {
    Arm64::<Geometry>::pa_from_gfn(Gfn(gfn))
}

/// Encodes a table or page descriptor, including the access flag.
fn page<Geometry: PagingGeometry>(gfn: u64) -> u64 {
    frame::<Geometry>(gfn).0 | (1 << 10) | 3
}

/// Builds a complete page walk and returns descriptor addresses root-first.
fn hierarchy<Geometry: PagingGeometry>(
    driver: &MockDriver<Geometry>,
    ctx: AddressContext,
    next_frame: u64,
    output: u64,
) -> Vec<Pa> {
    let control = Geometry::control();
    let mut level = control.start_level();
    let mut table = ctx.root;
    let mut next_frame = next_frame;
    let mut entries = Vec::new();
    loop {
        let entry = table + control.index(ctx.va, level) * 8;
        entries.push(entry);
        if level == PageTableLevel::L3 {
            driver.write_descriptor(entry, page::<Geometry>(output));
            break;
        }
        driver.write_descriptor(entry, page::<Geometry>(next_frame));
        table = frame::<Geometry>(next_frame);
        next_frame += 1;
        level = level.next().expect("non-leaf level");
    }
    entries
}

/// Converts events into comparable mapping observations without discarding
/// order.
fn events(events: Vec<PageTableMonitorEvent>) -> Vec<(bool, AddressContext, Pa)> {
    events
        .into_iter()
        .map(|event| match event {
            PageTableMonitorEvent::PageIn(update) => (true, update.ctx, update.pa),
            PageTableMonitorEvent::PageOut(update) => (false, update.ctx, update.pa),
        })
        .collect()
}

/// Exercises absent, page-in, replacement, attribute-only, and page-out
/// changes.
fn mapping_transitions<Geometry: PagingGeometry>(va: Va) -> Result<(), VmiError> {
    let driver = MockDriver::<Geometry>::new();
    let ctx = AddressContext::new(va, frame::<Geometry>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let leaf = *entries.last().expect("leaf descriptor");
    driver.write_descriptor(leaf, 0);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Geometry>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    assert_eq!(monitor.monitored_entries(), entries.len());
    assert_eq!(monitor.paged_in_entries(), 0);

    assert!(monitor.mark_dirty_entry(leaf + 3, VIEW, VCPU));
    vmi.driver().write_descriptor(leaf, page::<Geometry>(0x80));
    let offset = Geometry::control().offset(va, PageTableLevel::L3);
    let first = frame::<Geometry>(0x80) + offset;
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(true, ctx, first)]
    );

    assert!(monitor.mark_dirty_entry(leaf + 7, VIEW, VCPU));
    vmi.driver().write_descriptor(leaf, page::<Geometry>(0x90));
    let second = frame::<Geometry>(0x90) + offset;
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, ctx, first), (true, ctx, second)]
    );

    monitor.mark_dirty_entry(leaf, VIEW, VCPU);
    vmi.driver()
        .write_descriptor(leaf, page::<Geometry>(0x90) | (1 << 54));
    assert!(monitor.process_dirty_entries(&vmi, VCPU)?.is_empty());
    monitor.mark_dirty_entry(leaf, VIEW, VCPU);
    vmi.driver().write_descriptor(leaf, 2);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, ctx, second)]
    );
    assert_eq!(monitor.paged_in_entries(), 0);
    monitor.unmonitor_by_force(&vmi, ctx, VIEW)?;
    assert_eq!(monitor.monitored_tables(), 0);
    assert_eq!(monitor.monitored_entries(), 0);
    Ok(())
}

/// Checks the complete 4KB L0-through-L3 lifecycle with nonzero indices.
#[test]
fn mapping_transitions_4k() -> Result<(), VmiError> {
    mapping_transitions::<Granule4KVa48>(Va((1 << 39) | (2 << 30) | (3 << 21) | (4 << 12) | 0x123))
}

/// Checks the 16KB L1 root and full-width indices in the upper VA half.
#[test]
fn mapping_transitions_16k_high_indices() -> Result<(), VmiError> {
    mapping_transitions::<Granule16KVa47>(Va(0xffff_8000_0000_0000
        | (2047 << 36)
        | (2046 << 25)
        | (2045 << 14)
        | 0x3abc))
}

/// Exercises table-to-block-to-table conversion without stranding old tables.
fn block_conversion<Geometry: PagingGeometry>() -> Result<(), VmiError> {
    let driver = MockDriver::<Geometry>::new();
    let ctx = AddressContext::new(Va(0x12345), frame::<Geometry>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let parent = entries[entries.len() - 2];
    let old_leaf = *entries.last().expect("leaf");
    let old_table = Arm64::<Geometry>::gfn_from_pa(old_leaf);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Geometry>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    let page_offset = Geometry::control().offset(ctx.va, PageTableLevel::L3);
    let old_pa = frame::<Geometry>(0x80) + page_offset;
    let block_base = 1 << Geometry::control().level_shift(PageTableLevel::L2);
    vmi.driver()
        .write_descriptor(parent, block_base | (1 << 10) | 1);
    monitor.mark_dirty_entry(parent, VIEW, VCPU);
    let block_pa = Pa(block_base + ctx.va.0);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, ctx, old_pa), (true, ctx, block_pa)]
    );
    assert_eq!(monitor.monitored_tables(), entries.len() - 1);
    assert_eq!(vmi.driver().access(old_table, VIEW), MemoryAccess::RWX);

    let new_leaf =
        frame::<Geometry>(0x40) + Geometry::control().index(ctx.va, PageTableLevel::L3) * 8;
    vmi.driver()
        .write_descriptor(new_leaf, page::<Geometry>(0xa0));
    vmi.driver()
        .write_descriptor(parent, page::<Geometry>(0x40));
    monitor.mark_dirty_entry(parent, VIEW, VCPU);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, ctx, block_pa),
            (true, ctx, frame::<Geometry>(0xa0) + page_offset)
        ]
    );
    assert_eq!(monitor.monitored_tables(), entries.len());
    assert_eq!(vmi.driver().access(Gfn(0x40), VIEW), MemoryAccess::RX);
    monitor.unmonitor_all(&vmi);
    assert_eq!(monitor.monitored_tables(), 0);
    assert_eq!(vmi.driver().access(Gfn(0x40), VIEW), MemoryAccess::RWX);
    Ok(())
}

/// Checks legal 4KB L2 blocks and subtree protection replacement.
#[test]
fn block_table_conversion_4k() -> Result<(), VmiError> {
    block_conversion::<Granule4KVa48>()
}

/// Checks legal 16KB 32MB blocks and subtree protection replacement.
#[test]
fn block_table_conversion_16k() -> Result<(), VmiError> {
    block_conversion::<Granule16KVa47>()
}

/// Checks legal 4KB L1 blocks and rejects reserved descriptors at every level.
#[test]
fn legal_l1_block_and_reserved_descriptors() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule4KVa48>::new();
    let ctx = AddressContext::new(Va(0x12345678), frame::<Granule4KVa48>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule4KVa48>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    monitor.mark_dirty_entry(entries[1], VIEW, VCPU);
    vmi.driver().write_descriptor(entries[1], 0x40000001);
    let observed = events(monitor.process_dirty_entries(&vmi, VCPU)?);
    assert_eq!(observed.last(), Some(&(true, ctx, Pa(0x52345678))));
    assert_eq!(monitor.monitored_entries(), 2);
    monitor.mark_dirty_entry(entries[1], VIEW, VCPU);
    vmi.driver().write_descriptor(entries[1], 0x40001001);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, ctx, Pa(0x52345678))]
    );
    monitor.mark_dirty_entry(entries[0], VIEW, VCPU);
    vmi.driver().write_descriptor(entries[0], 1);
    assert!(monitor.process_dirty_entries(&vmi, VCPU)?.is_empty());
    assert_eq!(monitor.monitored_entries(), 1);
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Rejects illegal 16KB L1 blocks, reserved low address bits, and L3 blocks.
#[test]
fn malformed_16k_descriptors_do_not_map() -> Result<(), VmiError> {
    for invalid_level in [PageTableLevel::L1, PageTableLevel::L2, PageTableLevel::L3] {
        let driver = MockDriver::<Granule16KVa47>::new();
        let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
        let entries = hierarchy(&driver, ctx, 0x11, 0x80);
        let index = invalid_level as usize - PageTableLevel::L1 as usize;
        let malformed = match invalid_level {
            PageTableLevel::L1 => 1,
            PageTableLevel::L2 => page::<Granule16KVa47>(0x12) | 0x1000,
            PageTableLevel::L3 => 1,
            PageTableLevel::L0 => unreachable!("16KB root is L1"),
        };
        driver.write_descriptor(entries[index], malformed);
        let vmi = core(driver)?;
        let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
        monitor.monitor(&vmi, ctx, VIEW, "target")?;
        assert_eq!(monitor.paged_in_entries(), 0);
        assert_eq!(monitor.monitored_entries(), index + 1);
        monitor.mark_dirty_entry(entries[index], VIEW, VCPU);
        vmi.driver().write_descriptor(
            entries[index],
            if invalid_level == PageTableLevel::L3 {
                page::<Granule16KVa47>(0x80)
            }
            else {
                page::<Granule16KVa47>(0x11 + index as u64)
            },
        );
        assert_eq!(
            events(monitor.process_dirty_entries(&vmi, VCPU)?),
            vec![(true, ctx, frame::<Granule16KVa47>(0x80))]
        );
        monitor.unmonitor_all(&vmi);
    }
    Ok(())
}

/// Processes a parent replacement before an obsolete dirty leaf exactly once.
#[test]
fn parent_and_leaf_dirty_batch_observes_only_final_subtree() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0x4123), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    assert!(monitor.mark_dirty_entry(entries[2], VIEW, VCPU));
    assert!(monitor.mark_dirty_entry(entries[0], VIEW, VCPU));
    vmi.driver()
        .write_descriptor(entries[2], page::<Granule16KVa47>(0x90));
    vmi.driver()
        .write_descriptor(entries[0], page::<Granule16KVa47>(0x30));
    let new_parent = frame::<Granule16KVa47>(0x30);
    let new_leaf = frame::<Granule16KVa47>(0x31) + 8;
    vmi.driver()
        .write_descriptor(new_parent, page::<Granule16KVa47>(0x31));
    vmi.driver()
        .write_descriptor(new_leaf, page::<Granule16KVa47>(0xa0));
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, ctx, frame::<Granule16KVa47>(0x80) + 0x123),
            (true, ctx, frame::<Granule16KVa47>(0xa0) + 0x123),
        ]
    );
    assert_eq!(monitor.monitored_tables(), 3);
    assert_eq!(vmi.driver().access(Gfn(0x11), VIEW), MemoryAccess::RWX);
    assert_eq!(vmi.driver().access(Gfn(0x12), VIEW), MemoryAccess::RWX);
    assert!(monitor.process_dirty_entries(&vmi, VCPU)?.is_empty());
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Preserves root byte offsets and distinguishes registrations sharing a page.
#[test]
fn distinct_roots_with_byte_offsets_share_protection() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule4KVa48>::new();
    let first = AddressContext::new(Va(0x123), frame::<Granule4KVa48>(0x10) + 0x80);
    let second = AddressContext::new(first.va, frame::<Granule4KVa48>(0x10) + 0x100);
    let first_entries = hierarchy(&driver, first, 0x11, 0x80);
    let second_entries = hierarchy(&driver, second, 0x21, 0x90);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule4KVa48>>::new();
    monitor.monitor(&vmi, first, VIEW, "first")?;
    monitor.monitor(&vmi, second, VIEW, "second")?;
    assert_eq!(monitor.monitored_tables(), 7);
    assert_eq!(monitor.monitored_entries(), 8);
    vmi.driver().write_descriptor(first_entries[0], 0);
    monitor.mark_dirty_entry(first_entries[0] + 1, VIEW, VCPU);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, first, Pa(0x80123))]
    );
    assert_eq!(monitor.paged_in_entries(), 1);
    assert_eq!(monitor.monitored_tables(), 4);
    monitor.unmonitor(&vmi, first, VIEW)?;
    assert_eq!(vmi.driver().access(Gfn(0x10), VIEW), MemoryAccess::RX);
    monitor.mark_dirty_entry(*second_entries.last().expect("second leaf"), VIEW, VCPU);
    monitor.unmonitor(&vmi, second, VIEW)?;
    assert!(monitor.process_dirty_entries(&vmi, VCPU)?.is_empty());
    assert_eq!(monitor.monitored_tables(), 0);
    assert_eq!(vmi.driver().access(Gfn(0x10), VIEW), MemoryAccess::RWX);
    Ok(())
}

/// Rejects a root index outside its physical page without acquiring protection.
#[test]
fn root_descriptor_bounds_fail_without_leaking_references() -> Result<(), VmiError> {
    let vmi = core(MockDriver::<Granule16KVa47>::new())?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    let ctx = AddressContext::new(Va(2047 << 36), frame::<Granule16KVa47>(0x10) + 8);
    assert!(matches!(
        monitor.monitor(&vmi, ctx, VIEW, "target"),
        Err(VmiError::OutOfBounds)
    ));
    assert_eq!(monitor.monitored_entries(), 0);
    assert_eq!(monitor.monitored_tables(), 0);
    Ok(())
}

/// Balances repeated registrations, shared descriptors, and captured
/// protections.
#[test]
fn shared_registrations_restore_exact_permissions_on_last_release() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let first = AddressContext::new(Va(0x4123), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, first, 0x11, 0x80);
    let second = AddressContext::new(Va(0x8123), first.root);
    driver.write_descriptor(
        frame::<Granule16KVa47>(0x12) + 16,
        page::<Granule16KVa47>(0x90),
    );
    let permissions = [
        (Gfn(0x10), MemoryAccess::RWX),
        (Gfn(0x11), MemoryAccess::RW),
        (Gfn(0x12), MemoryAccess::RX),
    ];
    for &(gfn, access) in &permissions {
        driver.seed_access(gfn, VIEW, access);
    }
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, first, VIEW, "first")?;
    monitor.monitor(&vmi, first, VIEW, "duplicate")?;
    monitor.monitor(&vmi, second, VIEW, "second")?;
    assert_eq!(monitor.monitored_entries(), 4);
    assert_eq!(monitor.paged_in_entries(), 2);
    for &(gfn, access) in &permissions {
        assert_eq!(vmi.driver().access(gfn, VIEW), access & !MemoryAccess::W);
    }
    monitor.unmonitor(&vmi, first, VIEW)?;
    assert_eq!(monitor.monitored_entries(), 4);
    monitor.unmonitor(&vmi, first, VIEW)?;
    assert_eq!(monitor.monitored_entries(), entries.len());
    assert_eq!(monitor.paged_in_entries(), 1);
    monitor.unmonitor_by_force(&vmi, second, VIEW)?;
    assert_eq!(monitor.monitored_tables(), 0);
    for &(gfn, access) in &permissions {
        assert_eq!(vmi.driver().access(gfn, VIEW), access);
    }
    Ok(())
}

/// Preserves an older registration's pending mapping change when an alias
/// joins.
#[test]
fn registration_does_not_mask_shared_dirty_snapshot() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let first = AddressContext::new(Va(0x4123), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, first, 0x11, 0x80);
    let second = AddressContext::new(Va(0x4124), first.root);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, first, VIEW, "first")?;
    monitor.mark_dirty_entry(entries[2], VIEW, VCPU);
    vmi.driver()
        .write_descriptor(entries[2], page::<Granule16KVa47>(0x90));
    monitor.monitor(&vmi, second, VIEW, "second")?;
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, first, frame::<Granule16KVa47>(0x80) + 0x123),
            (true, first, frame::<Granule16KVa47>(0x90) + 0x123),
        ]
    );
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Detects pair stores and a store crossing a physical table-page boundary.
#[test]
fn wide_stores_mark_all_view_dependencies_and_remain_vcpu_local() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let first = AddressContext::new(Va(2047 << 14), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, first, 0x11, 0x80);
    let adjacent = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x20));
    hierarchy(&driver, adjacent, 0x21, 0x90);
    driver.write_descriptor(frame::<Granule16KVa47>(0x21), page::<Granule16KVa47>(0x13));
    driver.write_descriptor(frame::<Granule16KVa47>(0x13), page::<Granule16KVa47>(0x90));
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, first, VIEW, "first")?;
    monitor.monitor(&vmi, adjacent, VIEW, "adjacent")?;
    assert!(monitor.mark_dirty_entry(entries[2] + 3, VIEW, VCPU));
    assert!(monitor.mark_dirty_entry(entries[2] + 3, VIEW, VCPU));
    let bytes = [
        page::<Granule16KVa47>(0xa0).to_le_bytes(),
        page::<Granule16KVa47>(0xb0).to_le_bytes(),
    ]
    .concat();
    vmi.driver().write_bytes(entries[2], &bytes);
    assert!(monitor.process_dirty_entries(&vmi, VcpuId(1))?.is_empty());
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, first, frame::<Granule16KVa47>(0x80)),
            (true, first, frame::<Granule16KVa47>(0xa0)),
            (false, adjacent, frame::<Granule16KVa47>(0x90)),
            (true, adjacent, frame::<Granule16KVa47>(0xb0)),
        ]
    );
    monitor.unmonitor_all(&vmi);
    assert!(!monitor.mark_dirty_entry(entries[2], VIEW, VCPU));
    Ok(())
}

/// Detects an ordinary pair store whose first descriptor is not monitored.
#[test]
fn pair_store_starting_before_monitored_descriptor_is_detected() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule4KVa48>::new();
    let ctx = AddressContext::new(Va(0x2000), frame::<Granule4KVa48>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let leaf = entries[3];
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule4KVa48>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    assert!(monitor.mark_dirty_entry(leaf - 8, VIEW, VCPU));
    let bytes = [
        0u64.to_le_bytes(),
        page::<Granule4KVa48>(0x90).to_le_bytes(),
    ]
    .concat();
    vmi.driver().write_bytes(leaf - 8, &bytes);
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![(false, ctx, Pa(0x80000)), (true, ctx, Pa(0x90000))]
    );
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Preserves another view's protections and pending work during view cleanup.
#[test]
fn view_cleanup_is_independent() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let other = View(1);
    driver.seed_access(Gfn(0x10), other, MemoryAccess::RW);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "first")?;
    monitor.monitor(&vmi, ctx, other, "other")?;
    monitor.mark_dirty_entry(entries[2], other, VCPU);
    monitor.unmonitor_view(&vmi, VIEW);
    assert_eq!(monitor.monitored_tables(), 3);
    assert_eq!(vmi.driver().access(Gfn(0x10), VIEW), MemoryAccess::RWX);
    assert_eq!(vmi.driver().access(Gfn(0x10), other), MemoryAccess::R);
    vmi.driver().write_descriptor(entries[2], 0);
    let observed = monitor.process_dirty_entries(&vmi, VCPU)?;
    assert!(
        matches!(observed.as_slice(), [PageTableMonitorEvent::PageOut(update)] if update.view == other)
    );
    monitor.unmonitor_all(&vmi);
    assert_eq!(monitor.monitored_tables(), 0);
    assert_eq!(vmi.driver().access(Gfn(0x10), other), MemoryAccess::RW);
    Ok(())
}

/// Keeps failed protection restoration owned until an explicit retry succeeds.
#[test]
fn force_cleanup_propagates_restore_failure_and_can_retry() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    hierarchy(&driver, ctx, 0x11, 0x80);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    monitor.monitor(&vmi, ctx, VIEW, "duplicate")?;
    vmi.driver().fail_protection.set(true);
    assert!(matches!(
        monitor.unmonitor_by_force(&vmi, ctx, VIEW),
        Err(VmiError::OutOfBounds)
    ));
    assert_eq!(monitor.monitored_tables(), 3);
    assert_eq!(vmi.driver().access(Gfn(0x12), VIEW), MemoryAccess::RX);
    monitor.unmonitor_by_force(&vmi, ctx, VIEW)?;
    assert_eq!(monitor.monitored_entries(), 0);
    assert_eq!(monitor.monitored_tables(), 0);
    assert_eq!(vmi.driver().access(Gfn(0x12), VIEW), MemoryAccess::RWX);
    Ok(())
}

/// Rolls back first-registration acquisition failures without orphaning
/// entries.
#[test]
fn failed_monitor_acquisition_leaves_no_protection() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    hierarchy(&driver, ctx, 0x11, 0x80);
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    vmi.driver().fail_read.set(Some(Gfn(0x12)));
    assert!(matches!(
        monitor.monitor(&vmi, ctx, VIEW, "target"),
        Err(VmiError::OutOfBounds)
    ));
    assert_eq!(monitor.monitored_tables(), 0);
    vmi.driver().fail_read.set(None);
    vmi.driver().fail_protection.set(true);
    assert!(matches!(
        monitor.monitor(&vmi, ctx, VIEW, "target"),
        Err(VmiError::OutOfBounds)
    ));
    assert_eq!(monitor.monitored_entries(), 0);
    assert_eq!(monitor.monitored_tables(), 0);
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    assert_eq!(monitor.paged_in_entries(), 1);
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Handles a physical descriptor used at different levels by two roots.
#[test]
fn shared_descriptors_keep_levels_per_registration() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let first = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, first, 0x11, 0x80);
    let second = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x11));
    driver.write_descriptor(frame::<Granule16KVa47>(0x80), page::<Granule16KVa47>(0x90));
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, first, VIEW, "first")?;
    monitor.monitor(&vmi, second, VIEW, "second")?;
    assert_eq!(monitor.monitored_entries(), 4);
    assert_eq!(monitor.monitored_tables(), 4);
    monitor.mark_dirty_entry(entries[2], VIEW, VCPU);
    vmi.driver()
        .write_descriptor(entries[2], page::<Granule16KVa47>(0xa0));
    vmi.driver()
        .write_descriptor(frame::<Granule16KVa47>(0xa0), page::<Granule16KVa47>(0xb0));
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, first, frame::<Granule16KVa47>(0x80)),
            (true, first, frame::<Granule16KVa47>(0xa0)),
            (false, second, frame::<Granule16KVa47>(0x90)),
            (true, second, frame::<Granule16KVa47>(0xb0)),
        ]
    );
    assert_eq!(monitor.monitored_tables(), 4);
    assert_eq!(vmi.driver().access(Gfn(0x80), VIEW), MemoryAccess::RWX);
    monitor.unmonitor(&vmi, first, VIEW)?;
    assert_eq!(monitor.monitored_tables(), 3);
    assert_eq!(monitor.paged_in_entries(), 1);
    monitor.unmonitor(&vmi, second, VIEW)?;
    assert_eq!(monitor.monitored_tables(), 0);
    Ok(())
}

/// Emits teardown and setup when a replaced table retains the same output page.
#[test]
fn subtree_replacement_preserves_out_before_in_for_same_physical_page() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    driver.write_descriptor(frame::<Granule16KVa47>(0x30), page::<Granule16KVa47>(0x80));
    let vmi = core(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    monitor.mark_dirty_entry(entries[1], VIEW, VCPU);
    vmi.driver()
        .write_descriptor(entries[1], page::<Granule16KVa47>(0x30));
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, ctx, frame::<Granule16KVa47>(0x80)),
            (true, ctx, frame::<Granule16KVa47>(0x80)),
        ]
    );
    assert_eq!(vmi.driver().access(Gfn(0x12), VIEW), MemoryAccess::RWX);
    assert_eq!(vmi.driver().access(Gfn(0x30), VIEW), MemoryAccess::RX);
    monitor.unmonitor_all(&vmi);
    Ok(())
}

/// Rereads completed guest writes even when the core's default cache is
/// enabled.
#[test]
fn dirty_processing_does_not_reuse_cached_table_bytes() -> Result<(), VmiError> {
    let driver = MockDriver::<Granule16KVa47>::new();
    let ctx = AddressContext::new(Va(0), frame::<Granule16KVa47>(0x10));
    let entries = hierarchy(&driver, ctx, 0x11, 0x80);
    let vmi = VmiCore::new(driver)?;
    let mut monitor = PageTableMonitor::<MockDriver<Granule16KVa47>>::new();
    monitor.monitor(&vmi, ctx, VIEW, "target")?;
    vmi.read_page(Gfn(0x12))?;
    monitor.mark_dirty_entry(entries[2], VIEW, VCPU);
    vmi.driver()
        .write_descriptor(entries[2], page::<Granule16KVa47>(0x90));
    assert_eq!(
        events(monitor.process_dirty_entries(&vmi, VCPU)?),
        vec![
            (false, ctx, frame::<Granule16KVa47>(0x80)),
            (true, ctx, frame::<Granule16KVa47>(0x90)),
        ]
    );
    monitor.unmonitor_all(&vmi);
    Ok(())
}
