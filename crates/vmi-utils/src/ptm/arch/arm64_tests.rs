use std::{cell::RefCell, collections::HashMap};

use vmi_arch_arm64::{Arm64, Granule, PageTableEntry, PageTableLevel};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, Hfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId,
    View, VmiCore, VmiDriver, VmiError, VmiInfo, VmiMappedPage, VmiQueryProtection, VmiRead,
    VmiSetProtection,
};

use super::super::{PageTableMonitor, PageTableMonitorEvent};

///////////////////////////////////////////////////////////////////////////////
// Mock Driver
///////////////////////////////////////////////////////////////////////////////

struct MockPtmDriver {
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,
}

impl MockPtmDriver {
    fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
        }
    }

    /// Inserts a blank 4KB page at the given GFN.
    fn insert_page(&self, gfn: Gfn) {
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
    }

    /// Writes a stage-1 descriptor at the given physical address.
    fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        let gfn = Arm64::gfn_from_pa(pa);
        let offset = Arm64::pa_offset(pa) as usize;
        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&gfn)
            .unwrap_or_else(|| panic!("no page at {:?}", gfn));
        page[offset..offset + 8].copy_from_slice(&pte.0.to_le_bytes());
    }
}

/// Builds a valid table or page descriptor (`0b11`) pointing at `gfn`.
///
/// At L0-L2 this is a table descriptor; at L3 the same encoding is a page
/// descriptor. The access flag is irrelevant to the monitor, so it is left
/// clear.
fn make_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | 0b11)
}

/// Builds a valid block descriptor (`0b01`) pointing at `gfn`.
///
/// Only meaningful at L1 (1GB block) and L2 (2MB block).
fn make_block_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | 0b01)
}

/// Builds an invalid (paged-out) descriptor.
fn make_not_present_pte() -> PageTableEntry {
    PageTableEntry(0)
}

impl VmiDriver for MockPtmDriver {
    type Architecture = Arm64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: 4096,
            page_shift: 12,
            host_page_size: 4096,
            host_page_shift: 12,
            max_gfn: Gfn(0xFFFF),
            vcpus: 1,
        })
    }
}

impl VmiRead for MockPtmDriver {
    fn read_page(&self, frame: Hfn) -> Result<VmiMappedPage, VmiError> {
        // The mock reports a 4K host page (host_page_size == page_size), so the
        // host frame is the guest frame the page store is keyed by.
        let gfn = Gfn::new(frame.into());
        let pages = self.pages.borrow();
        let page = pages.get(&gfn).ok_or(VmiError::Other("page not found"))?;
        Ok(VmiMappedPage::new(page.clone()))
    }
}

impl VmiQueryProtection for MockPtmDriver {
    fn memory_access(&self, _gfn: Gfn, _view: View) -> Result<MemoryAccess, VmiError> {
        Ok(MemoryAccess::RW)
    }
}

impl VmiSetProtection for MockPtmDriver {
    fn set_memory_access(
        &self,
        _gfn: Gfn,
        _view: View,
        _access: MemoryAccess,
    ) -> Result<(), VmiError> {
        Ok(())
    }

    fn set_memory_access_with_options(
        &self,
        _gfn: Gfn,
        _view: View,
        _access: MemoryAccess,
        _options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
// Test Helpers
///////////////////////////////////////////////////////////////////////////////

/// Page table GFNs used in tests.
const L0_GFN: Gfn = Gfn(1);
const L1_GFN: Gfn = Gfn(2);
const L2_GFN: Gfn = Gfn(3);
const L3_GFN: Gfn = Gfn(4);
const DATA_GFN: Gfn = Gfn(5);

const VIEW: View = View(0);
const VCPU: VcpuId = VcpuId(0);

/// VA = 0x1000: L0[0] -> L1[0] -> L2[0] -> L3[1] -> DATA.
const TEST_VA: Va = Va(0x1000);

fn root_pa() -> Pa {
    Arm64::pa_from_gfn(L0_GFN)
}

fn test_ctx() -> AddressContext {
    AddressContext::new(TEST_VA, root_pa())
}

fn l3_entry_pa() -> Pa {
    Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8
}

fn l2_entry_pa() -> Pa {
    Arm64::pa_from_gfn(L2_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8
}

fn l1_entry_pa() -> Pa {
    Arm64::pa_from_gfn(L1_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8
}

fn l0_entry_pa() -> Pa {
    Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8
}

fn expected_data_pa() -> Pa {
    Arm64::pa_from_gfn(DATA_GFN) + Arm64::va_offset(TEST_VA)
}

/// Builds a full L0 -> L1 -> L2 -> L3 -> DATA chain in the mock driver.
fn build_full_hierarchy(driver: &MockPtmDriver) {
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(L2_GFN);
    driver.insert_page(L3_GFN);
    driver.insert_page(DATA_GFN);

    let l0_entry_pa =
        Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_entry_pa, make_pte(L1_GFN));

    let l1_entry_pa =
        Arm64::pa_from_gfn(L1_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8;
    driver.write_pte(l1_entry_pa, make_pte(L2_GFN));

    driver.write_pte(l2_entry_pa(), make_pte(L3_GFN));
    driver.write_pte(l3_entry_pa(), make_pte(DATA_GFN));
}

/// Builds an L0 -> L1 -> L2(block) -> DATA chain (2MB block, no L3 level).
fn build_block_hierarchy(driver: &MockPtmDriver) {
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(L2_GFN);
    driver.insert_page(DATA_GFN);

    let l0_entry_pa =
        Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_entry_pa, make_pte(L1_GFN));

    let l1_entry_pa =
        Arm64::pa_from_gfn(L1_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8;
    driver.write_pte(l1_entry_pa, make_pte(L2_GFN));

    driver.write_pte(l2_entry_pa(), make_block_pte(DATA_GFN));
}

/// Physical address of a 2MB block leaf: bits [20:0] of the VA index into it.
fn expected_block_pa(gfn: Gfn) -> Pa {
    Arm64::pa_from_gfn(gfn) + (TEST_VA.0 & 0x1f_ffff)
}

fn make_vmi(driver: MockPtmDriver) -> Result<VmiCore<MockPtmDriver>, VmiError> {
    let mut vmi = VmiCore::new(driver)?;
    vmi.disable_gfn_cache();
    Ok(vmi)
}

///////////////////////////////////////////////////////////////////////////////
// Monitor / Unmonitor
///////////////////////////////////////////////////////////////////////////////

#[test]
fn monitor_already_paged_in_address() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // All 4 levels (L0-L3) should be monitored.
    assert_eq!(ptm.monitored_tables(), 4);
    // One entry per level = 4 entries.
    assert_eq!(ptm.monitored_entries(), 4);
    // The address is already resolved.
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn monitor_unmonitor_lifecycle() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.monitored_entries(), 0);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn monitor_not_present_at_every_level() -> Result<(), VmiError> {
    // The L0 entry itself is invalid.
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 1); // Only the L0 page.
    assert_eq!(ptm.monitored_entries(), 1); // Only the L0 entry.
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-out
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_out_at_l3_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Invalidate the L3 entry to simulate page-out.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn page_out_at_l2_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Invalidate the L2 entry - the entire L3 subtree becomes unreachable.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // The L3 table should be unmonitored now (L0, L1, L2 remain).
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-in
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_in_at_l3_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Invalidate the L3 entry before monitoring, so the VA is not paged in.
    driver.write_pte(l3_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);

    // Restore the L3 entry to make it valid.
    vmi.driver().write_pte(l3_entry_pa(), make_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Blocks (large pages)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn block_initial_monitoring() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // Resolves as a 2MB block at L2: 3 levels monitored (L0, L1, L2).
    assert_eq!(ptm.monitored_tables(), 3);
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn block_page_out() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Invalidate the L2 block descriptor.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn block_pfn_change() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Repoint the block at a different frame.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_block_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // A frame change tears down the old mapping and sets up the new one.
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_block_pa(new_data_gfn)));
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Dirty Processing
///////////////////////////////////////////////////////////////////////////////

#[test]
fn hierarchical_dirty_ordering() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Invalidate the L2 entry to page out the entire L3 subtree, and mark both
    // the L2 and L3 entries dirty in the same batch. Processing the higher
    // (root-most, L2) entry first must remove the L3 entry from monitoring so
    // the stale L3 dirty entry is safely skipped.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());

    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    let page_outs = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect::<Vec<_>>();
    assert!(
        !page_outs.is_empty(),
        "expected at least one PageOut event from hierarchical dirty"
    );
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn higher_level_invalidation_suppresses_stale_leaf_change() -> Result<(), VmiError> {
    // In one dirty batch the L2 entry is invalidated (paging out the whole L3
    // subtree) while the L3 leaf is repointed to a different frame. Processing
    // the root-most (L2) entry first tears down the L3 entry, so the stale L3
    // change is skipped and exactly one PageOut is reported. The wrong
    // (leaf-first) order would emit a spurious PageIn for the repointed leaf
    // followed by a second PageOut. This guards the ascending dirty sort.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let other_data_gfn = Gfn(10);
    driver.insert_page(other_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Invalidate L2 (pages out the L3 subtree) and repoint the L3 leaf.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());
    vmi.driver()
        .write_pte(l3_entry_pa(), make_pte(other_data_gfn));

    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 1, "stale leaf change must be suppressed");
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn no_dirty_entries_returns_empty() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert!(events.is_empty());

    Ok(())
}

#[test]
fn mark_dirty_nonexistent_entry_returns_false() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    let bogus_pa = Pa(0xDEAD_0000);
    let marked = ptm.mark_dirty_entry(bogus_pa, VIEW, VCPU);
    assert!(!marked);

    Ok(())
}

#[test]
fn dirty_entry_unchanged_produces_no_events() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // Mark dirty without changing the entry value.
    let marked = ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert!(
        events.is_empty(),
        "unchanged entry should produce no events"
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn multiple_dirty_marks_same_entry_deduplicates() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    vmi.driver()
        .write_pte(l3_entry_pa(), make_pte(new_data_gfn));
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // Should deduplicate: only one PageOut + one PageIn.
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(..)));

    Ok(())
}

#[test]
fn process_dirty_after_unmonitor_is_safe() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;

    // Processing after unmonitor should produce no events.
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert!(events.is_empty());

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-out (upper levels)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_out_at_l1_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Invalidate the L1 entry - L2 and L3 subtrees become unreachable.
    vmi.driver()
        .write_pte(l1_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // L2 and L3 tables should be unmonitored now (L0, L1 remain).
    assert_eq!(ptm.monitored_tables(), 2);

    Ok(())
}

#[test]
fn page_out_at_l0_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Invalidate the L0 entry - the entire L1/L2/L3 subtree becomes unreachable.
    vmi.driver()
        .write_pte(l0_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(l0_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // L1, L2, L3 tables should be unmonitored (only L0 remains).
    assert_eq!(ptm.monitored_tables(), 1);

    Ok(())
}

#[test]
fn page_out_at_shared_level_affects_all_vas() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // VA2 = 0x2000 shares L0/L1/L2/L3 with VA = 0x1000.
    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);

    let l3_entry_pa2 =
        Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(va2, PageTableLevel::L3) * 8;
    driver.write_pte(l3_entry_pa2, make_pte(data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // Invalidate the L2 entry - both VAs lose their mapping.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());

    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    let page_outs = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect::<Vec<_>>();
    assert_eq!(page_outs.len(), 2);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-in (upper levels)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_in_at_l2_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Invalidate the L2 entry before monitoring so the L3 subtree is not resolved.
    driver.write_pte(l2_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only L0, L1, L2 are monitored (L3 is unreachable).
    assert_eq!(ptm.monitored_tables(), 3);

    // Restore the L2 entry - the L3 subtree becomes reachable.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(L3_GFN));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_in_at_l1_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Invalidate the L1 entry before monitoring.
    driver.write_pte(l1_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only L0, L1 are monitored (L2 and L3 are unreachable).
    assert_eq!(ptm.monitored_tables(), 2);

    // Restore the L1 entry - L2/L3/DATA chain is already intact.
    vmi.driver().write_pte(l1_entry_pa(), make_pte(L2_GFN));

    let marked = ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_in_at_l0_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Invalidate the L0 entry before monitoring.
    driver.write_pte(l0_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only L0 is monitored (everything below is unreachable).
    assert_eq!(ptm.monitored_tables(), 1);

    // Restore the L0 entry - the entire L1/L2/L3/DATA chain is intact.
    vmi.driver().write_pte(l0_entry_pa(), make_pte(L1_GFN));

    let marked = ptm.mark_dirty_entry(l0_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-out / Page-in Round Trips
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_out_then_page_in_round_trip() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Page out at L3 level.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert_eq!(ptm.paged_in_entries(), 0);

    // Page back in at L3 level.
    vmi.driver().write_pte(l3_entry_pa(), make_pte(DATA_GFN));
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn page_out_at_l2_then_page_in_restores_subtree() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Page out at L2 level.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert_eq!(ptm.monitored_tables(), 3); // L3 removed.
    assert_eq!(ptm.paged_in_entries(), 0);

    // Restore L2 entry - L3 subtree should be re-walked.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(L3_GFN));
    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.monitored_tables(), 4); // L3 restored.
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Additional Monitor / Unmonitor
///////////////////////////////////////////////////////////////////////////////

#[test]
fn multiple_vas_sharing_page_table_pages() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // VA2 = 0x2000 shares L0/L1/L2 with VA = 0x1000 but has a different L3 entry.
    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);

    let l3_entry_pa2 =
        Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(va2, PageTableLevel::L3) * 8;
    driver.write_pte(l3_entry_pa2, make_pte(data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;

    // Both share L0, L1, L2, L3 pages = 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 2);

    // Unmonitor first VA - shared tables should remain.
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Unmonitor second VA - now all tables should be gone.
    ptm.unmonitor(&vmi, ctx2, VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_all_clears_state() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    ptm.unmonitor_all(&vmi);
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.monitored_entries(), 0);

    Ok(())
}

#[test]
fn monitor_remonitor_same_va() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Monitor the same VA again - should update in-place without doubling.
    ptm.monitor(&vmi, test_ctx(), VIEW, "test2")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Unmonitor once should fully clean up.
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_nonexistent_va_is_noop() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.monitored_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_with_not_present_intermediate() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Invalidate the L2 entry before monitoring so the L3 subtree is not resolved.
    driver.write_pte(l2_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 3); // L0, L1, L2

    // Unmonitor should succeed even though the L2 entry is not present.
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.monitored_entries(), 0);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_view_only_affects_target_view() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let view0 = View(0);
    let view1 = View(1);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), view0, "v0")?;
    ptm.monitor(&vmi, test_ctx(), view1, "v1")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    ptm.unmonitor_view(&vmi, view0);
    assert_eq!(ptm.paged_in_entries(), 1);

    ptm.unmonitor_view(&vmi, view1);
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 0);

    Ok(())
}

#[test]
fn different_roots_are_independent() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build a second root with its own hierarchy.
    let l0_2_gfn = Gfn(20);
    let l1_2_gfn = Gfn(21);
    let l2_2_gfn = Gfn(22);
    let l3_2_gfn = Gfn(23);
    let data_2_gfn = Gfn(24);
    driver.insert_page(l0_2_gfn);
    driver.insert_page(l1_2_gfn);
    driver.insert_page(l2_2_gfn);
    driver.insert_page(l3_2_gfn);
    driver.insert_page(data_2_gfn);

    let root2 = Arm64::pa_from_gfn(l0_2_gfn);

    driver.write_pte(
        Arm64::pa_from_gfn(l0_2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8,
        make_pte(l1_2_gfn),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l1_2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8,
        make_pte(l2_2_gfn),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l2_2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8,
        make_pte(l3_2_gfn),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l3_2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8,
        make_pte(data_2_gfn),
    );

    let ctx2 = AddressContext::new(TEST_VA, root2);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "root1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "root2")?;

    // Two completely separate hierarchies = 8 tables.
    assert_eq!(ptm.monitored_tables(), 8);
    assert_eq!(ptm.paged_in_entries(), 2);

    // Page out root1's L3 entry.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    // root2 is unaffected.
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Frame Change
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_change_pfn_at_l3_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the L3 entry frame while keeping it valid.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data_gfn) + Arm64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn page_change_pfn_at_l2_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate L3 -> DATA2 chain.
    let new_l3_gfn = Gfn(10);
    let new_data_gfn = Gfn(11);
    driver.insert_page(new_l3_gfn);
    driver.insert_page(new_data_gfn);

    let new_l3_entry_pa =
        Arm64::pa_from_gfn(new_l3_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8;
    driver.write_pte(new_l3_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the L2 entry to point to the new L3 page.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(new_l3_gfn));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data_gfn) + Arm64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old L3 unmonitored, new L3 monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_change_pfn_at_l1_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate L2 -> L3 -> DATA2 chain.
    let new_l2_gfn = Gfn(10);
    let new_l3_gfn = Gfn(11);
    let new_data_gfn = Gfn(12);
    driver.insert_page(new_l2_gfn);
    driver.insert_page(new_l3_gfn);
    driver.insert_page(new_data_gfn);

    let new_l2_entry_pa =
        Arm64::pa_from_gfn(new_l2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8;
    driver.write_pte(new_l2_entry_pa, make_pte(new_l3_gfn));

    let new_l3_entry_pa =
        Arm64::pa_from_gfn(new_l3_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8;
    driver.write_pte(new_l3_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the L1 entry to point to the new L2 page.
    vmi.driver().write_pte(l1_entry_pa(), make_pte(new_l2_gfn));

    let marked = ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data_gfn) + Arm64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old L2+L3 unmonitored, new L2+L3 monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_change_pfn_at_l0_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate L1 -> L2 -> L3 -> DATA2 chain.
    let new_l1_gfn = Gfn(10);
    let new_l2_gfn = Gfn(11);
    let new_l3_gfn = Gfn(12);
    let new_data_gfn = Gfn(13);
    driver.insert_page(new_l1_gfn);
    driver.insert_page(new_l2_gfn);
    driver.insert_page(new_l3_gfn);
    driver.insert_page(new_data_gfn);

    let new_l1_entry_pa =
        Arm64::pa_from_gfn(new_l1_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8;
    driver.write_pte(new_l1_entry_pa, make_pte(new_l2_gfn));

    let new_l2_entry_pa =
        Arm64::pa_from_gfn(new_l2_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8;
    driver.write_pte(new_l2_entry_pa, make_pte(new_l3_gfn));

    let new_l3_entry_pa =
        Arm64::pa_from_gfn(new_l3_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8;
    driver.write_pte(new_l3_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the L0 entry to point to the new L1 page.
    vmi.driver().write_pte(l0_entry_pa(), make_pte(new_l1_gfn));

    let marked = ptm.mark_dirty_entry(l0_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data_gfn) + Arm64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old L1+L2+L3 unmonitored, new L1+L2+L3 monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn permission_bit_change_produces_no_events() -> Result<(), VmiError> {
    // Changing only non-structural attribute bits (access flag, AP) must not
    // produce events.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Set the access flag (bit 10) and AP[2] read-only (bit 7) on the L3 entry,
    // changing neither the valid bit, the type bits, nor the output address.
    let original_pte = make_pte(DATA_GFN);
    let modified_pte = PageTableEntry(original_pte.0 | (1 << 10) | (1 << 7));
    assert!(modified_pte.valid());
    assert_eq!(
        modified_pte.output_frame(Granule::_4K),
        original_pte.output_frame(Granule::_4K)
    );

    vmi.driver().write_pte(l3_entry_pa(), modified_pte);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert!(events.is_empty());
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Shared Page Tables
///////////////////////////////////////////////////////////////////////////////

#[test]
fn shared_higher_level_pfn_change_rebuilds_both_vas() -> Result<(), VmiError> {
    // Two VAs share L0/L1/L2. When the L2 entry frame changes, both VAs should
    // page out and then page in via the new L3 page.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);
    let l3_entry_pa2 =
        Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(va2, PageTableLevel::L3) * 8;
    driver.write_pte(l3_entry_pa2, make_pte(data2_gfn));

    // Build a new L3 page with entries for both VAs.
    let new_l3_gfn = Gfn(20);
    let new_data1_gfn = Gfn(21);
    let new_data2_gfn = Gfn(22);
    driver.insert_page(new_l3_gfn);
    driver.insert_page(new_data1_gfn);
    driver.insert_page(new_data2_gfn);

    let new_l3_entry1 =
        Arm64::pa_from_gfn(new_l3_gfn) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8;
    driver.write_pte(new_l3_entry1, make_pte(new_data1_gfn));

    let new_l3_entry2 =
        Arm64::pa_from_gfn(new_l3_gfn) + Arm64::va_index_for(va2, PageTableLevel::L3) * 8;
    driver.write_pte(new_l3_entry2, make_pte(new_data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // Change the L2 entry to point to the new L3 page.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(new_l3_gfn));
    ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    let page_outs = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect::<Vec<_>>();
    let page_ins = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(..)))
        .collect::<Vec<_>>();
    assert_eq!(page_outs.len(), 2);
    assert_eq!(page_ins.len(), 2);
    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

#[test]
fn shared_physical_page_at_different_levels_across_roots() -> Result<(), VmiError> {
    // Two roots share a physical page at different hierarchy levels:
    //   Root1 uses Gfn(3) as an L2 table (entry at offset 8)
    //   Root2 uses Gfn(3) as an L3 table (entry at offset 8)
    //
    // VA1 = 0x200000 has L2 index = 1, VA2 = 0x1000 has L3 index = 1. Both
    // produce the same physical address: pa_from_gfn(3) + 1*8.
    //
    // This tests that dirty processing uses the correct per-VA level, not a
    // single level stored on the shared entry.

    let driver = MockPtmDriver::new();
    let shared_gfn = Gfn(3);

    // Root1: L0(1) -> L1(2) -> L2(3)[1] -> L3(4)[0] -> DATA(5)
    let l0_1 = Gfn(1);
    let l1_1 = Gfn(2);
    let l3_1 = Gfn(4);
    let data_1 = Gfn(5);
    let va1 = Va(0x200000);

    driver.insert_page(l0_1);
    driver.insert_page(l1_1);
    driver.insert_page(shared_gfn);
    driver.insert_page(l3_1);
    driver.insert_page(data_1);

    driver.write_pte(
        Arm64::pa_from_gfn(l0_1) + Arm64::va_index_for(va1, PageTableLevel::L0) * 8,
        make_pte(l1_1),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l1_1) + Arm64::va_index_for(va1, PageTableLevel::L1) * 8,
        make_pte(shared_gfn),
    );
    let shared_pa =
        Arm64::pa_from_gfn(shared_gfn) + Arm64::va_index_for(va1, PageTableLevel::L2) * 8;
    driver.write_pte(shared_pa, make_pte(l3_1));
    driver.write_pte(
        Arm64::pa_from_gfn(l3_1) + Arm64::va_index_for(va1, PageTableLevel::L3) * 8,
        make_pte(data_1),
    );

    // Root2: L0(10) -> L1(11) -> L2(12)[0] -> L3(3)[1] -> Gfn(4)
    // L3(3)[1] is the SAME physical descriptor as L2(3)[1] for root1.
    // Root2 interprets the descriptor value (pointing to Gfn(4)) as leaf data.
    let l0_2 = Gfn(10);
    let l1_2 = Gfn(11);
    let l2_2 = Gfn(12);
    let va2 = Va(0x1000);

    driver.insert_page(l0_2);
    driver.insert_page(l1_2);
    driver.insert_page(l2_2);

    driver.write_pte(
        Arm64::pa_from_gfn(l0_2) + Arm64::va_index_for(va2, PageTableLevel::L0) * 8,
        make_pte(l1_2),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l1_2) + Arm64::va_index_for(va2, PageTableLevel::L1) * 8,
        make_pte(l2_2),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l2_2) + Arm64::va_index_for(va2, PageTableLevel::L2) * 8,
        make_pte(shared_gfn),
    );

    // Sanity: both VAs index the same offset within the shared page.
    assert_eq!(
        Arm64::va_index_for(va1, PageTableLevel::L2),
        Arm64::va_index_for(va2, PageTableLevel::L3),
    );

    // Pre-allocate pages for the post-change walk.
    let new_gfn = Gfn(20);
    let new_data_1 = Gfn(21);
    driver.insert_page(new_gfn);
    driver.insert_page(new_data_1);
    // Root1 will walk Gfn(20) as an L3 page. Set up an L3 entry for VA1.
    driver.write_pte(
        Arm64::pa_from_gfn(new_gfn) + Arm64::va_index_for(va1, PageTableLevel::L3) * 8,
        make_pte(new_data_1),
    );

    let root1_pa = Arm64::pa_from_gfn(l0_1);
    let root2_pa = Arm64::pa_from_gfn(l0_2);
    let ctx1 = AddressContext::new(va1, root1_pa);
    let ctx2 = AddressContext::new(va2, root2_pa);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, ctx1, VIEW, "root1_l2")?;
    ptm.monitor(&vmi, ctx2, VIEW, "root2_l3")?;

    assert_eq!(ptm.paged_in_entries(), 2);

    // Change the shared descriptor from Gfn(4) to Gfn(20).
    vmi.driver().write_pte(shared_pa, make_pte(new_gfn));

    ptm.mark_dirty_entry(shared_pa, VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    // Root1 (L2 level): non-leaf frame change -> PageOut + walk into Gfn(20)
    //   as L3 -> PageIn at pa_from_gfn(21).
    // Root2 (L3 level): leaf frame change -> PageOut + PageIn at pa_from_gfn(20).
    let page_outs = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect::<Vec<_>>();
    let page_ins = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(..)))
        .collect::<Vec<_>>();
    assert_eq!(page_outs.len(), 2, "both VAs should page out");
    assert_eq!(page_ins.len(), 2, "both VAs should page in");

    // Verify root1 PageIn: resolved through new L3(20) -> DATA(21).
    let root1_expected_pa =
        Arm64::pa_from_gfn(new_data_1) + Arm64::va_offset_for(va1, PageTableLevel::L3);
    let root1_in = events.iter().find_map(|e| match e {
        PageTableMonitorEvent::PageIn(u) if u.ctx == ctx1 => Some(u),
        _ => None,
    });
    assert_eq!(
        root1_in.unwrap().pa,
        root1_expected_pa,
        "root1 should resolve through the new L3 subtree"
    );

    // Verify root2 PageIn: direct leaf at Gfn(20).
    let root2_expected_pa =
        Arm64::pa_from_gfn(new_gfn) + Arm64::va_offset_for(va2, PageTableLevel::L3);
    let root2_in = events.iter().find_map(|e| match e {
        PageTableMonitorEvent::PageIn(u) if u.ctx == ctx2 => Some(u),
        _ => None,
    });
    assert_eq!(
        root2_in.unwrap().pa,
        root2_expected_pa,
        "root2 should resolve as a leaf at L3 level"
    );

    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Blocks (page-in, 1GB)
///////////////////////////////////////////////////////////////////////////////

#[test]
fn block_page_in() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    // Invalidate the L2 block before monitoring so it is not resolved.
    driver.write_pte(l2_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 3);

    // Restore the L2 entry as a block.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_block_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_block_pa(DATA_GFN)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn block_1gb_at_l1_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();

    // Build hierarchy: L0 -> L1(block 1GB) -> DATA
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(DATA_GFN);

    let l0_pa = Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_pa, make_pte(L1_GFN));

    // L1 entry as a 1GB block.
    driver.write_pte(l1_entry_pa(), make_block_pte(DATA_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // 2 levels monitored: L0 and L1 (the block terminates the walk).
    assert_eq!(ptm.monitored_tables(), 2);
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn block_1gb_pfn_change() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(DATA_GFN);

    let l0_pa = Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_pa, make_pte(L1_GFN));
    driver.write_pte(l1_entry_pa(), make_block_pte(DATA_GFN));

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the 1GB block frame.
    vmi.driver()
        .write_pte(l1_entry_pa(), make_block_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    // 1GB block: offset is bits [29:0] of the VA.
    let expected_pa = Arm64::pa_from_gfn(new_data_gfn) + (TEST_VA.0 & 0x3fff_ffff);
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_pa));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Block Transitions
///////////////////////////////////////////////////////////////////////////////

#[test]
fn transition_regular_to_block_same_frame() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Flip the L2 entry from a table (pointing to L3_GFN) to a block at the same
    // frame: now it directly maps a 2MB block at L3_GFN.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_block_pte(L3_GFN));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_block_pa(L3_GFN)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old L3 unmonitored; now L0, L1, L2 = 3 tables.
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn transition_regular_to_block_different_frame() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the L2 entry from a table to a block at a new frame.
    vmi.driver()
        .write_pte(l2_entry_pa(), make_block_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_block_pa(new_data_gfn)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old L3 unmonitored; now L0, L1, L2 = 3 tables.
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn transition_block_to_regular_same_frame() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Flip the L2 entry from a block to a table with the same frame (DATA_GFN).
    // DATA_GFN is now treated as an L3 table; it is zeroed, so the L3 entry is
    // invalid and there is no new mapping.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // The new L3 table (DATA_GFN) is now monitored: L0, L1, L2, DATA_GFN = 4.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn transition_block_to_regular_different_frame() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_block_hierarchy(&driver);

    let new_l3_gfn = Gfn(10);
    driver.insert_page(new_l3_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Change the L2 entry from a block to a table pointing at a new L3 page.
    // The new L3 page is zeroed, so the L3 entry is invalid.
    vmi.driver().write_pte(l2_entry_pa(), make_pte(new_l3_gfn));

    let marked = ptm.mark_dirty_entry(l2_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // The new L3 table is now monitored: L0, L1, L2, new_l3 = 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn transition_block_to_block_frame_change_at_l1() -> Result<(), VmiError> {
    // A 1GB block at L1 changes frame while remaining a block.
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(DATA_GFN);

    let l0_pa = Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_pa, make_pte(L1_GFN));
    driver.write_pte(l1_entry_pa(), make_block_pte(DATA_GFN));

    let new_gfn = Gfn(10);
    driver.insert_page(new_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 2);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the frame of the 1GB block.
    vmi.driver()
        .write_pte(l1_entry_pa(), make_block_pte(new_gfn));
    ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    let expected_pa = Arm64::pa_from_gfn(new_gfn) + (TEST_VA.0 & 0x3fff_ffff);
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_pa));
    assert_eq!(ptm.monitored_tables(), 2);
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Multi-vCPU
///////////////////////////////////////////////////////////////////////////////

const VCPU_0: VcpuId = VcpuId(0);
const VCPU_1: VcpuId = VcpuId(1);

#[test]
fn dirty_entry_is_per_vcpu() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the L3 entry and mark dirty on vCPU 0.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_pte(new_data_gfn));
    let marked = ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU_0);
    assert!(marked);

    // Process on vCPU 1 - should see nothing.
    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert!(
        events.is_empty(),
        "vcpu 1 should not see vcpu 0's dirty entries"
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    // Process on vCPU 0 - should see the change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data_gfn) + Arm64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn independent_dirty_entries_across_vcpus() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);
    let l3_entry_pa2 =
        Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(va2, PageTableLevel::L3) * 8;
    driver.write_pte(l3_entry_pa2, make_pte(data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let new_data1 = Gfn(10);
    let new_data2 = Gfn(11);
    driver.insert_page(new_data1);
    driver.insert_page(new_data2);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // vCPU 0 changes VA1's L3 entry.
    vmi.driver().write_pte(l3_entry_pa(), make_pte(new_data1));
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU_0);

    // vCPU 1 changes VA2's L3 entry.
    vmi.driver().write_pte(l3_entry_pa2, make_pte(new_data2));
    ptm.mark_dirty_entry(l3_entry_pa2, VIEW, VCPU_1);

    // Process vCPU 1 first - should only see VA2's change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert_eq!(events.len(), 2, "vcpu 1 should see VA2 page-out + page-in");
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == ctx2));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data2) + Arm64::va_offset(va2)));

    // Process vCPU 0 - should only see VA1's change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2, "vcpu 0 should see VA1 page-out + page-in");
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Arm64::pa_from_gfn(new_data1) + Arm64::va_offset(TEST_VA)));

    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

#[test]
fn process_empty_vcpu_returns_empty() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert!(events.is_empty());
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn same_entry_marked_dirty_by_multiple_vcpus() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Both vCPUs mark the same entry dirty.
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU_0);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU_1);

    // Change the descriptor.
    vmi.driver()
        .write_pte(l3_entry_pa(), make_pte(new_data_gfn));

    // vCPU 0 processes - sees the change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(..)));

    // vCPU 1 processes - the entry's cached value now matches the current
    // descriptor, so there are no events.
    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert!(
        events.is_empty(),
        "vcpu 1 should see no change after vcpu 0 already processed"
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Regression Tests
///////////////////////////////////////////////////////////////////////////////

#[test]
fn walk_subtree_does_not_mask_pending_dirty_entry() -> Result<(), VmiError> {
    // walk_subtree must not overwrite cached_pte on an existing entry, or it
    // masks pending dirty changes for other VAs.
    //
    // Setup: two roots, same VA (0x1000), with a shared L3 page.
    //   Root1: L0(30) -> L1(31) -> L2(32) -> L3_old(33) -> DATA_1(34)
    //   Root2: L0(40) -> L1(41) -> L2(42) -> L3_shared(50) -> DATA_2(51)
    //
    // Then simultaneously:
    //   1. Root1's L2 entry changes to point to L3_shared (instead of L3_old).
    //   2. L3_shared's entry changes to point to new_DATA_2(52).
    //
    // Both entries are marked dirty. The L2 entry (root-most) is processed
    // first, so walk_subtree for Root1 walks into L3_shared, which Root2 already
    // monitors. If walk_subtree overwrote cached_pte, Root2's change would be
    // masked.

    let driver = MockPtmDriver::new();

    // Root1 hierarchy.
    let l0_1 = Gfn(30);
    let l1_1 = Gfn(31);
    let l2_1 = Gfn(32);
    let l3_old = Gfn(33);
    let data_1 = Gfn(34);
    for gfn in [l0_1, l1_1, l2_1, l3_old, data_1] {
        driver.insert_page(gfn);
    }

    driver.write_pte(
        Arm64::pa_from_gfn(l0_1) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8,
        make_pte(l1_1),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l1_1) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8,
        make_pte(l2_1),
    );
    let l2_1_entry_pa =
        Arm64::pa_from_gfn(l2_1) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8;
    driver.write_pte(l2_1_entry_pa, make_pte(l3_old));
    driver.write_pte(
        Arm64::pa_from_gfn(l3_old) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8,
        make_pte(data_1),
    );

    // Root2 hierarchy.
    let l0_2 = Gfn(40);
    let l1_2 = Gfn(41);
    let l2_2 = Gfn(42);
    let l3_shared = Gfn(50);
    let data_2 = Gfn(51);
    let new_data_2 = Gfn(52);
    for gfn in [l0_2, l1_2, l2_2, l3_shared, new_data_2] {
        driver.insert_page(gfn);
    }

    driver.write_pte(
        Arm64::pa_from_gfn(l0_2) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8,
        make_pte(l1_2),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l1_2) + Arm64::va_index_for(TEST_VA, PageTableLevel::L1) * 8,
        make_pte(l2_2),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(l2_2) + Arm64::va_index_for(TEST_VA, PageTableLevel::L2) * 8,
        make_pte(l3_shared),
    );
    let shared_l3_entry_pa =
        Arm64::pa_from_gfn(l3_shared) + Arm64::va_index_for(TEST_VA, PageTableLevel::L3) * 8;
    driver.write_pte(shared_l3_entry_pa, make_pte(data_2));

    let root1 = Arm64::pa_from_gfn(l0_1);
    let root2 = Arm64::pa_from_gfn(l0_2);
    let ctx1 = AddressContext::new(TEST_VA, root1);
    let ctx2 = AddressContext::new(TEST_VA, root2);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, ctx1, VIEW, "root1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "root2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // Simultaneous changes.
    // 1. Root1's L2 entry now points to L3_shared.
    vmi.driver().write_pte(l2_1_entry_pa, make_pte(l3_shared));
    // 2. L3_shared's entry now points to new_DATA_2.
    vmi.driver()
        .write_pte(shared_l3_entry_pa, make_pte(new_data_2));

    // Mark both dirty on the same vCPU.
    ptm.mark_dirty_entry(l2_1_entry_pa, VIEW, VCPU_0);
    ptm.mark_dirty_entry(shared_l3_entry_pa, VIEW, VCPU_0);

    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;

    // Root2 must get a PageOut for the old DATA_2 mapping.
    let root2_page_outs = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(u) if u.ctx == ctx2))
        .collect::<Vec<_>>();
    assert!(
        !root2_page_outs.is_empty(),
        "Root2 must get PageOut when its L3 entry frame changes"
    );

    // Root2 must also get a PageIn for new_DATA_2.
    let root2_page_ins = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(u) if u.ctx == ctx2))
        .collect::<Vec<_>>();
    assert!(
        !root2_page_ins.is_empty(),
        "Root2 must get PageIn for new_DATA_2"
    );

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// AArch64 descriptor-encoding and regime specifics
///////////////////////////////////////////////////////////////////////////////

#[test]
fn upper_attribute_bits_do_not_affect_resolution() -> Result<(), VmiError> {
    // The output frame occupies descriptor bits [47:12]. Upper attribute /
    // software bits (>= 48, e.g. PXN/UXN/software-use) and low attribute bits
    // (2..11) must not leak into the frame, and changing only those bits must
    // produce no events. Bit 50 in particular guards against an erroneous
    // 52-bit-PA mask.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    let attr_bits = (1u64 << 50) | (1u64 << 54) | (1u64 << 55) | (1u64 << 10) | (1u64 << 7);
    let leaf = PageTableEntry(make_pte(DATA_GFN).0 | attr_bits);
    assert!(leaf.valid());
    assert_eq!(
        leaf.output_frame(Granule::_4K),
        DATA_GFN,
        "attribute bits must not leak into the output frame"
    );

    vmi.driver().write_pte(l3_entry_pa(), leaf);
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert!(
        events.is_empty(),
        "attribute-only change must produce no events"
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn l0_block_descriptor_is_not_a_leaf() -> Result<(), VmiError> {
    // AArch64 has no block descriptors at L0. A block-encoded (0b01) L0 entry is
    // neither a leaf nor a table to descend, so the walk records the entry and
    // stops without paging in. (Without the "valid but not a table" guard the
    // walk would wrongly descend into the block target as if it were a table.)
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);
    driver.write_pte(l0_entry_pa(), make_block_pte(L1_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 1);
    assert_eq!(ptm.monitored_entries(), 1);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn l3_block_descriptor_is_not_a_leaf() -> Result<(), VmiError> {
    // At L3 only a page descriptor (0b11) is a leaf. A block-encoded (0b01) L3
    // entry is a reserved encoding: the walk records it but does not resolve the
    // VA.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);
    driver.write_pte(l3_entry_pa(), make_block_pte(DATA_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn page_in_from_software_pte_at_l3() -> Result<(), VmiError> {
    // A paged-out page leaves a non-zero "software" descriptor at L3 with the
    // valid bit clear (the Windows transition / prototype PTE analog, carrying a
    // frame in the address field). The monitor must treat it as not present and
    // emit PageIn when it becomes a valid page. Presence keys on bit 0 alone.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let software_pte = PageTableEntry((DATA_GFN.0 << 12) | (1 << 11));
    assert!(!software_pte.valid());
    driver.write_pte(l3_entry_pa(), software_pte);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0, "software PTE is not present");
    assert_eq!(ptm.monitored_tables(), 4);

    // The page faults in: the L3 slot becomes a valid page descriptor.
    vmi.driver().write_pte(l3_entry_pa(), make_pte(DATA_GFN));
    ptm.mark_dirty_entry(l3_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn high_half_kernel_va_resolves() -> Result<(), VmiError> {
    // Kernel symbols live in the high half (bit 55 set, TTBR1). The walk must
    // extract per-level indices from a high VA without the upper bits corrupting
    // the entry addresses, and dirty processing must track the high VA.
    let driver = MockPtmDriver::new();

    // Canonical high-half VA (bits 48..63 set) with indices L0=1, L1=2, L2=3,
    // L3=4 in bits [47:12].
    let kva = Va((0xFFFFu64 << 48) | (1u64 << 39) | (2u64 << 30) | (3u64 << 21) | (4u64 << 12));
    let root = Arm64::pa_from_gfn(L0_GFN);

    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(L2_GFN);
    driver.insert_page(L3_GFN);
    driver.insert_page(DATA_GFN);

    driver.write_pte(
        Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(kva, PageTableLevel::L0) * 8,
        make_pte(L1_GFN),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(L1_GFN) + Arm64::va_index_for(kva, PageTableLevel::L1) * 8,
        make_pte(L2_GFN),
    );
    driver.write_pte(
        Arm64::pa_from_gfn(L2_GFN) + Arm64::va_index_for(kva, PageTableLevel::L2) * 8,
        make_pte(L3_GFN),
    );
    let kva_l3_entry =
        Arm64::pa_from_gfn(L3_GFN) + Arm64::va_index_for(kva, PageTableLevel::L3) * 8;
    driver.write_pte(kva_l3_entry, make_pte(DATA_GFN));

    let ctx = AddressContext::new(kva, root);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, ctx, VIEW, "kernel")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Page out the high VA at L3 and confirm it is tracked correctly.
    vmi.driver().write_pte(kva_l3_entry, make_not_present_pte());
    ptm.mark_dirty_entry(kva_l3_entry, VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == ctx));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn block_1gb_page_out() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(DATA_GFN);

    let l0_pa = Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_pa, make_pte(L1_GFN));
    driver.write_pte(l1_entry_pa(), make_block_pte(DATA_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 2);

    // Invalidate the 1GB block.
    vmi.driver()
        .write_pte(l1_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn block_1gb_page_in() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    driver.insert_page(L0_GFN);
    driver.insert_page(L1_GFN);
    driver.insert_page(DATA_GFN);

    let l0_pa = Arm64::pa_from_gfn(L0_GFN) + Arm64::va_index_for(TEST_VA, PageTableLevel::L0) * 8;
    driver.write_pte(l0_pa, make_pte(L1_GFN));
    // The 1GB block is invalid before monitoring.
    driver.write_pte(l1_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 2);

    // Restore the 1GB block.
    vmi.driver()
        .write_pte(l1_entry_pa(), make_block_pte(DATA_GFN));
    ptm.mark_dirty_entry(l1_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    let expected = Arm64::pa_from_gfn(DATA_GFN) + (TEST_VA.0 & 0x3fff_ffff);
    assert!(matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}
