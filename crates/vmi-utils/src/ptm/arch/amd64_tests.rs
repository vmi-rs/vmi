use std::{cell::RefCell, collections::HashMap};

use vmi_arch_amd64::{Amd64, PageTableEntry, PageTableLevel};
use vmi_core::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, Va, VcpuId,
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

    /// Writes a page table entry at the given physical address.
    fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        let gfn = Amd64::gfn_from_pa(pa);
        let offset = Amd64::pa_offset(pa) as usize;
        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&gfn)
            .unwrap_or_else(|| panic!("no page at {:?}", gfn));
        page[offset..offset + 8].copy_from_slice(&pte.0.to_le_bytes());
    }
}

fn make_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | 1)
}

fn make_large_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | (1 << 7) | 1)
}

fn make_not_present_pte() -> PageTableEntry {
    PageTableEntry(0)
}

impl VmiDriver for MockPtmDriver {
    type Architecture = Amd64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: 4096,
            page_shift: 12,
            max_gfn: Gfn(0xFFFF),
            vcpus: 1,
        })
    }
}

impl VmiRead for MockPtmDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
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
const PML4_GFN: Gfn = Gfn(1);
const PDPT_GFN: Gfn = Gfn(2);
const PD_GFN: Gfn = Gfn(3);
const PT_GFN: Gfn = Gfn(4);
const DATA_GFN: Gfn = Gfn(5);

const VIEW: View = View(0);
const VCPU: VcpuId = VcpuId(0);

/// VA = 0x1000: PML4[0] -> PDPT[0] -> PD[0] -> PT[1] -> DATA
const TEST_VA: Va = Va(0x1000);

fn root_pa() -> Pa {
    Amd64::pa_from_gfn(PML4_GFN)
}

fn test_ctx() -> AddressContext {
    AddressContext::new(TEST_VA, root_pa())
}

/// Builds a full PML4->PDPT->PD->PT->DATA chain in the mock driver.
fn build_full_hierarchy(driver: &MockPtmDriver) {
    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(PD_GFN);
    driver.insert_page(PT_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_entry_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_entry_pa, make_pte(PDPT_GFN));

    let pdpt_entry_pa =
        Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(pdpt_entry_pa, make_pte(PD_GFN));

    let pd_entry_pa =
        Amd64::pa_from_gfn(PD_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8;
    driver.write_pte(pd_entry_pa, make_pte(PT_GFN));

    let pt_entry_pa =
        Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(pt_entry_pa, make_pte(DATA_GFN));
}

fn pt_entry_pa() -> Pa {
    Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8
}

fn pd_entry_pa() -> Pa {
    Amd64::pa_from_gfn(PD_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8
}

fn pdpt_entry_pa() -> Pa {
    Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8
}

fn pml4_entry_pa() -> Pa {
    Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8
}

fn expected_data_pa() -> Pa {
    Amd64::pa_from_gfn(DATA_GFN) + Amd64::va_offset(TEST_VA)
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

    // All 4 levels should be monitored.
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
    // paged_in should be cleared on unmonitor.
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn multiple_vas_sharing_page_table_pages() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // VA2 = 0x2000 shares PML4/PDPT/PD with VA=0x1000 but has a different PT entry.
    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);

    let pt_entry_pa2 =
        Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(va2, PageTableLevel::Pt) * 8;
    driver.write_pte(pt_entry_pa2, make_pte(data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;

    // Both share PML4, PDPT, PD, PT pages = 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 2);

    // Unmonitor first VA - shared tables should remain.
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.paged_in_entries(), 1);
    // The 4 tables should still be monitored because VA2 uses them.
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
    // Note: paged_in is not cleared by unmonitor_all (known leak per plan).

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

    // Monitor the same VA again — should update in-place without doubling.
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
fn monitor_not_present_at_every_level() -> Result<(), VmiError> {
    // Monitoring a VA where the PML4 entry itself is not present.
    let driver = MockPtmDriver::new();
    driver.insert_page(PML4_GFN);
    // PML4 entry is zeroed (not present).

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 1); // Only PML4 page.
    assert_eq!(ptm.monitored_entries(), 1); // Only PML4 entry.
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_nonexistent_va_is_noop() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    // Unmonitor something that was never monitored.
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;
    assert_eq!(ptm.monitored_tables(), 0);
    assert_eq!(ptm.monitored_entries(), 0);

    Ok(())
}

#[test]
fn unmonitor_with_not_present_intermediate() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Zero the PD entry *before* monitoring so the PT subtree is not resolved.
    driver.write_pte(pd_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 3); // PML4, PDPT, PD

    // Unmonitor should succeed even though PD entry is not present.
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
    // View 1 should remain.
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

    // Build a second PML4 root with its own hierarchy.
    let pml4_2_gfn = Gfn(20);
    let pdpt_2_gfn = Gfn(21);
    let pd_2_gfn = Gfn(22);
    let pt_2_gfn = Gfn(23);
    let data_2_gfn = Gfn(24);
    driver.insert_page(pml4_2_gfn);
    driver.insert_page(pdpt_2_gfn);
    driver.insert_page(pd_2_gfn);
    driver.insert_page(pt_2_gfn);
    driver.insert_page(data_2_gfn);

    let root2 = Amd64::pa_from_gfn(pml4_2_gfn);

    driver.write_pte(
        Amd64::pa_from_gfn(pml4_2_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8,
        make_pte(pdpt_2_gfn),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pdpt_2_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8,
        make_pte(pd_2_gfn),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pd_2_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8,
        make_pte(pt_2_gfn),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pt_2_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8,
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

    // Page out root1's PT entry.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    // root2 is unaffected.
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// PFN Change
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_change_pfn_at_pt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the PT entry PFN while keeping it present.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // Should produce PageOut + PageIn.
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data_gfn) + Amd64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn page_change_pfn_at_pd_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate PT -> DATA2 chain.
    let new_pt_gfn = Gfn(10);
    let new_data_gfn = Gfn(11);
    driver.insert_page(new_pt_gfn);
    driver.insert_page(new_data_gfn);

    let new_pt_entry_pa =
        Amd64::pa_from_gfn(new_pt_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(new_pt_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the PD entry to point to the new PT page.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(new_pt_gfn));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data_gfn) + Amd64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old PT unmonitored, new PT monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_change_pfn_at_pdpt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate PD -> PT -> DATA2 chain.
    let new_pd_gfn = Gfn(10);
    let new_pt_gfn = Gfn(11);
    let new_data_gfn = Gfn(12);
    driver.insert_page(new_pd_gfn);
    driver.insert_page(new_pt_gfn);
    driver.insert_page(new_data_gfn);

    let new_pd_entry_pa =
        Amd64::pa_from_gfn(new_pd_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8;
    driver.write_pte(new_pd_entry_pa, make_pte(new_pt_gfn));

    let new_pt_entry_pa =
        Amd64::pa_from_gfn(new_pt_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(new_pt_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the PDPT entry to point to the new PD page.
    vmi.driver()
        .write_pte(pdpt_entry_pa(), make_pte(new_pd_gfn));

    let marked = ptm.mark_dirty_entry(pdpt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data_gfn) + Amd64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old PD+PT unmonitored, new PD+PT monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_change_pfn_at_pml4_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Build an alternate PDPT -> PD -> PT -> DATA2 chain.
    let new_pdpt_gfn = Gfn(10);
    let new_pd_gfn = Gfn(11);
    let new_pt_gfn = Gfn(12);
    let new_data_gfn = Gfn(13);
    driver.insert_page(new_pdpt_gfn);
    driver.insert_page(new_pd_gfn);
    driver.insert_page(new_pt_gfn);
    driver.insert_page(new_data_gfn);

    let new_pdpt_entry_pa =
        Amd64::pa_from_gfn(new_pdpt_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(new_pdpt_entry_pa, make_pte(new_pd_gfn));

    let new_pd_entry_pa =
        Amd64::pa_from_gfn(new_pd_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8;
    driver.write_pte(new_pd_entry_pa, make_pte(new_pt_gfn));

    let new_pt_entry_pa =
        Amd64::pa_from_gfn(new_pt_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(new_pt_entry_pa, make_pte(new_data_gfn));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change the PML4 entry to point to the new PDPT page.
    vmi.driver()
        .write_pte(pml4_entry_pa(), make_pte(new_pdpt_gfn));

    let marked = ptm.mark_dirty_entry(pml4_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data_gfn) + Amd64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old PDPT+PD+PT unmonitored, new PDPT+PD+PT monitored - still 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn permission_bit_change_produces_no_events() -> Result<(), VmiError> {
    // Changing only non-structural bits (accessed, dirty, etc.) should not
    // produce any events.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Set the accessed + dirty bits on the PT entry without changing PFN or present.
    let original_pte = make_pte(DATA_GFN);
    let modified_pte = PageTableEntry(original_pte.0 | (1 << 5) | (1 << 6));
    assert!(modified_pte.present());
    assert_eq!(modified_pte.pfn(), original_pte.pfn());

    vmi.driver().write_pte(pt_entry_pa(), modified_pte);
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    // No structural change → no events.
    assert!(events.is_empty());
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-out
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_out_at_pt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Zero the PT entry to simulate page-out.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_not_present_pte());

    // Mark the PT entry as dirty and process.
    let marked = ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn page_out_at_pd_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Zero the PD entry — the entire PT subtree becomes unreachable.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()
    ));
    assert_eq!(ptm.paged_in_entries(), 0);
    // PT table should be unmonitored now (PML4, PDPT, PD remain).
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn page_out_at_pdpt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Zero the PDPT entry - PD and PT subtrees become unreachable.
    vmi.driver()
        .write_pte(pdpt_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(pdpt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()
    ));
    assert_eq!(ptm.paged_in_entries(), 0);
    // PD and PT tables should be unmonitored now (PML4, PDPT remain).
    assert_eq!(ptm.monitored_tables(), 2);

    Ok(())
}

#[test]
fn page_out_at_pml4_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Zero the PML4 entry - the entire PDPT/PD/PT subtree becomes unreachable.
    vmi.driver()
        .write_pte(pml4_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(pml4_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()
    ));
    assert_eq!(ptm.paged_in_entries(), 0);
    // PDPT, PD, PT tables should be unmonitored (only PML4 remains).
    assert_eq!(ptm.monitored_tables(), 1);

    Ok(())
}

#[test]
fn page_out_at_shared_level_affects_all_vas() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // VA2 = 0x2000 shares PML4/PDPT/PD/PT with VA=0x1000.
    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);

    let pt_entry_pa2 =
        Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(va2, PageTableLevel::Pt) * 8;
    driver.write_pte(pt_entry_pa2, make_pte(data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // Zero the PD entry — both VAs lose their mapping.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_not_present_pte());

    ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // Both VAs should get PageOut events.
    let page_outs: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect();
    assert_eq!(page_outs.len(), 2);
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Page-in
///////////////////////////////////////////////////////////////////////////////

#[test]
fn page_in_at_pt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Zero the PT entry *before* monitoring, so the VA isn't paged in.
    driver.write_pte(pt_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);

    // Restore the PT entry to make it present.
    vmi.driver().write_pte(pt_entry_pa(), make_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn page_in_at_pd_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Zero the PD entry *before* monitoring so the PT subtree is not resolved.
    driver.write_pte(pd_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only PML4, PDPT, PD are monitored (PT is unreachable).
    assert_eq!(ptm.monitored_tables(), 3);

    // Restore the PD entry - the PT subtree becomes reachable, and
    // the PT entry already points to DATA, so we should get a PageIn.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(PT_GFN));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);
    // Now all 4 levels should be monitored.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn page_in_at_pdpt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Zero the PDPT entry *before* monitoring.
    driver.write_pte(pdpt_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only PML4, PDPT are monitored (PD and PT are unreachable).
    assert_eq!(ptm.monitored_tables(), 2);

    // Restore the PDPT entry - PD/PT/DATA chain is already intact.
    vmi.driver().write_pte(pdpt_entry_pa(), make_pte(PD_GFN));

    let marked = ptm.mark_dirty_entry(pdpt_entry_pa(), VIEW, VCPU);
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
fn page_in_at_pml4_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    // Zero the PML4 entry *before* monitoring.
    driver.write_pte(pml4_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    // Only PML4 is monitored (everything below is unreachable).
    assert_eq!(ptm.monitored_tables(), 1);

    // Restore the PML4 entry - the entire PDPT/PD/PT/DATA chain is intact.
    vmi.driver().write_pte(pml4_entry_pa(), make_pte(PDPT_GFN));

    let marked = ptm.mark_dirty_entry(pml4_entry_pa(), VIEW, VCPU);
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
    // Full round trip: paged in → page out → page in.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Page out at PT level.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert_eq!(ptm.paged_in_entries(), 0);

    // Page back in at PT level.
    vmi.driver().write_pte(pt_entry_pa(), make_pte(DATA_GFN));
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn page_out_at_pd_then_page_in_restores_subtree() -> Result<(), VmiError> {
    // Page out at PD level (removes PT monitoring), then page in restores it.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 4);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Page out at PD level.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_not_present_pte());
    ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert_eq!(ptm.monitored_tables(), 3); // PT removed.
    assert_eq!(ptm.paged_in_entries(), 0);

    // Restore PD entry → PT subtree should be re-walked.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(PT_GFN));
    ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(
        matches!(events[0], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_data_pa())
    );
    assert_eq!(ptm.monitored_tables(), 4); // PT restored.
    assert_eq!(ptm.paged_in_entries(), 1);

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

    // Mark both PD entry and PT entry as dirty (simulate write to page
    // containing PD and PT entries in the same event).
    // Zero the PD entry to simulate page-out of the entire PT.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_not_present_pte());
    // The PT entry is also dirty, but after processing the PD entry page-out,
    // the PT entry should be gone from monitoring.

    ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    // We expect a PageOut for our VA.
    let page_outs: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect();
    assert!(
        !page_outs.is_empty(),
        "expected at least one PageOut event from hierarchical dirty"
    );
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

    // Process without marking anything dirty.
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

    // Mark dirty an address that isn't a monitored entry.
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
    let marked = ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
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

    // Change PTE and mark dirty multiple times.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_pte(new_data_gfn));
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // Should deduplicate: only one PageOut + one PageIn.
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(..)));

    Ok(())
}

#[test]
fn process_dirty_after_unmonitor_is_safe() -> Result<(), VmiError> {
    // Mark dirty, then unmonitor, then process. Should not crash.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU);
    ptm.unmonitor(&vmi, test_ctx(), VIEW)?;

    // Processing after unmonitor should produce no events.
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert!(events.is_empty());

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Shared Page Tables
///////////////////////////////////////////////////////////////////////////////

#[test]
fn shared_higher_level_pfn_change_rebuilds_both_vas() -> Result<(), VmiError> {
    // Two VAs share PML4/PDPT/PD. When PD entry PFN changes, both VAs
    // should page out and then page in via the new PT page.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);
    let pt_entry_pa2 =
        Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(va2, PageTableLevel::Pt) * 8;
    driver.write_pte(pt_entry_pa2, make_pte(data2_gfn));

    // Build a new PT page with entries for both VAs.
    let new_pt_gfn = Gfn(20);
    let new_data1_gfn = Gfn(21);
    let new_data2_gfn = Gfn(22);
    driver.insert_page(new_pt_gfn);
    driver.insert_page(new_data1_gfn);
    driver.insert_page(new_data2_gfn);

    let new_pt_entry1 =
        Amd64::pa_from_gfn(new_pt_gfn) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(new_pt_entry1, make_pte(new_data1_gfn));

    let new_pt_entry2 =
        Amd64::pa_from_gfn(new_pt_gfn) + Amd64::va_index_for(va2, PageTableLevel::Pt) * 8;
    driver.write_pte(new_pt_entry2, make_pte(new_data2_gfn));

    let ctx2 = AddressContext::new(va2, root_pa());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "test2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // Change PD entry to point to new PT page.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(new_pt_gfn));
    ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    // 2 PageOuts + 2 PageIns.
    let page_outs: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect();
    let page_ins: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(..)))
        .collect();
    assert_eq!(page_outs.len(), 2);
    assert_eq!(page_ins.len(), 2);
    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

#[test]
fn shared_physical_page_at_different_levels_across_roots() -> Result<(), VmiError> {
    // Two roots share a physical page at different hierarchy levels:
    //   Root1 uses Gfn(3) as a PD table  (PD entry at offset 8)
    //   Root2 uses Gfn(3) as a PT table  (PT entry at offset 8)
    //
    // VA1=0x200000 has PD index=1, VA2=0x1000 has PT index=1.
    // Both produce the same physical address: pa_from_gfn(3) + 1*8.
    //
    // This tests that dirty processing uses the correct per-VA level,
    // not a single level stored on the shared entry.

    let driver = MockPtmDriver::new();
    let shared_gfn = Gfn(3);

    // ── Root1: PML4(1) -> PDPT(2) -> PD(3)[1] -> PT(4)[0] -> DATA(5) ──
    let pml4_1 = Gfn(1);
    let pdpt_1 = Gfn(2);
    let pt_1 = Gfn(4);
    let data_1 = Gfn(5);
    let va1 = Va(0x200000);

    driver.insert_page(pml4_1);
    driver.insert_page(pdpt_1);
    driver.insert_page(shared_gfn);
    driver.insert_page(pt_1);
    driver.insert_page(data_1);

    driver.write_pte(
        Amd64::pa_from_gfn(pml4_1) + Amd64::va_index_for(va1, PageTableLevel::Pml4) * 8,
        make_pte(pdpt_1),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pdpt_1) + Amd64::va_index_for(va1, PageTableLevel::Pdpt) * 8,
        make_pte(shared_gfn),
    );
    let shared_pa =
        Amd64::pa_from_gfn(shared_gfn) + Amd64::va_index_for(va1, PageTableLevel::Pd) * 8;
    driver.write_pte(shared_pa, make_pte(pt_1));
    driver.write_pte(
        Amd64::pa_from_gfn(pt_1) + Amd64::va_index_for(va1, PageTableLevel::Pt) * 8,
        make_pte(data_1),
    );

    // ── Root2: PML4(10) -> PDPT(11) -> PD(12)[0] -> PT(3)[1] -> Gfn(4) ──
    // PT(3)[1] is the SAME physical PTE as PD(3)[1] for root1.
    // Root2 interprets the PTE value (pointing to Gfn(4)) as leaf data.
    let pml4_2 = Gfn(10);
    let pdpt_2 = Gfn(11);
    let pd_2 = Gfn(12);
    let va2 = Va(0x1000);

    driver.insert_page(pml4_2);
    driver.insert_page(pdpt_2);
    driver.insert_page(pd_2);

    driver.write_pte(
        Amd64::pa_from_gfn(pml4_2) + Amd64::va_index_for(va2, PageTableLevel::Pml4) * 8,
        make_pte(pdpt_2),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pdpt_2) + Amd64::va_index_for(va2, PageTableLevel::Pdpt) * 8,
        make_pte(pd_2),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pd_2) + Amd64::va_index_for(va2, PageTableLevel::Pd) * 8,
        make_pte(shared_gfn),
    );

    // Sanity: both VAs index the same offset within the shared page.
    assert_eq!(
        Amd64::va_index_for(va1, PageTableLevel::Pd),
        Amd64::va_index_for(va2, PageTableLevel::Pt),
    );

    // Pre-allocate pages for the post-change walk.
    let new_gfn = Gfn(20);
    let new_data_1 = Gfn(21);
    driver.insert_page(new_gfn);
    driver.insert_page(new_data_1);
    // Root1 will walk Gfn(20) as a PT page. Set up a PT entry for VA1.
    driver.write_pte(
        Amd64::pa_from_gfn(new_gfn) + Amd64::va_index_for(va1, PageTableLevel::Pt) * 8,
        make_pte(new_data_1),
    );

    let root1_pa = Amd64::pa_from_gfn(pml4_1);
    let root2_pa = Amd64::pa_from_gfn(pml4_2);
    let ctx1 = AddressContext::new(va1, root1_pa);
    let ctx2 = AddressContext::new(va2, root2_pa);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, ctx1, VIEW, "root1_pd")?;
    ptm.monitor(&vmi, ctx2, VIEW, "root2_pt")?;

    assert_eq!(ptm.paged_in_entries(), 2);

    // Change the shared PTE from Gfn(4) to Gfn(20).
    vmi.driver().write_pte(shared_pa, make_pte(new_gfn));

    ptm.mark_dirty_entry(shared_pa, VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    // Root1 (PD level): non-leaf PFN change → PageOut + walk into Gfn(20)
    //   as PT → PageIn at pa_from_gfn(21).
    // Root2 (PT level): leaf PFN change → PageOut + PageIn at pa_from_gfn(20).
    let page_outs: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(..)))
        .collect();
    let page_ins: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(..)))
        .collect();
    assert_eq!(page_outs.len(), 2, "both VAs should page out");
    assert_eq!(page_ins.len(), 2, "both VAs should page in");

    // Verify root1 PageIn: resolved through new PT(20) -> DATA(21).
    let root1_expected_pa =
        Amd64::pa_from_gfn(new_data_1) + Amd64::va_offset_for(va1, PageTableLevel::Pt);
    let root1_in = events.iter().find_map(|e| match e {
        PageTableMonitorEvent::PageIn(u) if u.ctx == ctx1 => Some(u),
        _ => None,
    });
    assert_eq!(
        root1_in.unwrap().pa,
        root1_expected_pa,
        "root1 should resolve through new PT subtree"
    );

    // Verify root2 PageIn: direct leaf at Gfn(20).
    let root2_expected_pa =
        Amd64::pa_from_gfn(new_gfn) + Amd64::va_offset_for(va2, PageTableLevel::Pt);
    let root2_in = events.iter().find_map(|e| match e {
        PageTableMonitorEvent::PageIn(u) if u.ctx == ctx2 => Some(u),
        _ => None,
    });
    assert_eq!(
        root2_in.unwrap().pa,
        root2_expected_pa,
        "root2 should resolve as leaf at PT level"
    );

    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Large Pages
///////////////////////////////////////////////////////////////////////////////

/// Builds PML4->PDPT->PD(large)->DATA hierarchy (no PT level).
fn build_large_page_hierarchy(driver: &MockPtmDriver) {
    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(PD_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_pa, make_pte(PDPT_GFN));

    let pdpt_pa =
        Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(pdpt_pa, make_pte(PD_GFN));

    driver.write_pte(pd_entry_pa(), make_large_pte(DATA_GFN));
}

fn expected_large_page_pa(gfn: Gfn) -> Pa {
    // For a 2MB large page at PD level, the offset is bits [20:0] of the VA.
    Amd64::pa_from_gfn(gfn) + (TEST_VA.0 & 0x1f_ffff)
}

#[test]
fn large_page_initial_monitoring() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();

    // Build hierarchy up to PD level, then PD entry is a large page.
    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(PD_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_entry_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_entry_pa, make_pte(PDPT_GFN));

    let pdpt_entry_pa =
        Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(pdpt_entry_pa, make_pte(PD_GFN));

    // PD entry with large bit set, pointing to DATA_GFN as a 2MB page.
    let pd_entry_pa =
        Amd64::pa_from_gfn(PD_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8;
    driver.write_pte(pd_entry_pa, make_large_pte(DATA_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // Should resolve as a large page at PD level (3 levels monitored: PML4, PDPT, PD).
    assert_eq!(ptm.monitored_tables(), 3);
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn large_page_pfn_change() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_large_page_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Change the large page PFN.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_large_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_large_page_pa(new_data_gfn)));
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn large_page_page_out() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_large_page_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Zero the PD entry to make the large page not-present.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_not_present_pte());

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);

    Ok(())
}

#[test]
fn large_page_page_in() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_large_page_hierarchy(&driver);

    // Zero the PD entry *before* monitoring so the large page is not resolved.
    driver.write_pte(pd_entry_pa(), make_not_present_pte());

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 0);
    assert_eq!(ptm.monitored_tables(), 3);

    // Restore the PD entry as a large page.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_large_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_large_page_pa(DATA_GFN)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn large_page_1gb_at_pdpt_level() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();

    // Build hierarchy: PML4 -> PDPT(large 1GB) -> DATA
    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_pa, make_pte(PDPT_GFN));

    // PDPT entry with large bit set (1GB page).
    let pdpt_pa =
        Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(pdpt_pa, make_large_pte(DATA_GFN));

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;

    // 2 levels monitored: PML4 and PDPT (large page terminates the walk).
    assert_eq!(ptm.monitored_tables(), 2);
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn large_page_1gb_pfn_change() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();

    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_pa, make_pte(PDPT_GFN));

    let pdpt_pa =
        Amd64::pa_from_gfn(PDPT_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8;
    driver.write_pte(pdpt_pa, make_large_pte(DATA_GFN));

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change the 1GB page PFN.
    vmi.driver()
        .write_pte(pdpt_entry_pa(), make_large_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(pdpt_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    // 1GB page: offset is bits [29:0] of VA.
    let expected_pa = Amd64::pa_from_gfn(new_data_gfn) + (TEST_VA.0 & 0x3fff_ffff);
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u) if u.pa == expected_pa));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
// Large Page Transitions
///////////////////////////////////////////////////////////////////////////////

#[test]
fn large_page_transition_regular_to_large_same_pfn() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Flip the PD entry from regular (pointing to PT_GFN) to large (same PFN).
    // This changes from "follow PT_GFN as a page table" to "directly map 2MB
    // at PT_GFN".
    vmi.driver()
        .write_pte(pd_entry_pa(), make_large_pte(PT_GFN));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // PageOut(old mapping through PT) + PageIn(new large page mapping).
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_large_page_pa(PT_GFN)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old PT unmonitored; now PML4, PDPT, PD = 3 tables.
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn large_page_transition_regular_to_large_different_pfn() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 4);

    // Change PD entry from regular (pointing to PT_GFN) to large page at new_data_gfn.
    vmi.driver()
        .write_pte(pd_entry_pa(), make_large_pte(new_data_gfn));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // PageOut(old mapping through PT) + PageIn(new large page mapping).
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == expected_large_page_pa(new_data_gfn)));
    assert_eq!(ptm.paged_in_entries(), 1);
    // Old PT unmonitored; now PML4, PDPT, PD = 3 tables.
    assert_eq!(ptm.monitored_tables(), 3);

    Ok(())
}

#[test]
fn large_page_transition_large_to_regular_same_pfn() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_large_page_hierarchy(&driver);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Flip PD entry from large to regular with same PFN (DATA_GFN).
    // Now DATA_GFN is treated as a PT page. Since it's zeroed, the
    // PT entry will be not-present, so no PageIn for the new mapping.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(DATA_GFN));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // PageOut only - the new PT entry (from zeroed DATA page) is not present.
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // New PT table (DATA_GFN) is now monitored: PML4, PDPT, PD, DATA_GFN = 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn large_page_transition_large_to_regular_different_pfn() -> Result<(), VmiError> {
    let driver = MockPtmDriver::new();
    build_large_page_hierarchy(&driver);

    let new_pt_gfn = Gfn(10);
    driver.insert_page(new_pt_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);
    assert_eq!(ptm.monitored_tables(), 3);

    // Change PD entry from large page to regular, pointing to a new PT page.
    // Since new_pt_gfn is zeroed, the PT entry is not present.
    vmi.driver().write_pte(pd_entry_pa(), make_pte(new_pt_gfn));

    let marked = ptm.mark_dirty_entry(pd_entry_pa(), VIEW, VCPU);
    assert!(marked);

    let events = ptm.process_dirty_entries(&vmi, VCPU)?;
    // PageOut only - new PT entry is not present.
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert_eq!(ptm.paged_in_entries(), 0);
    // New PT table (new_pt_gfn) is now monitored: PML4, PDPT, PD, new_pt = 4 tables.
    assert_eq!(ptm.monitored_tables(), 4);

    Ok(())
}

#[test]
fn large_page_transition_large_to_large_pfn_change_at_pdpt() -> Result<(), VmiError> {
    // 1GB large page at PDPT level changes PFN while remaining large.
    let driver = MockPtmDriver::new();
    driver.insert_page(PML4_GFN);
    driver.insert_page(PDPT_GFN);
    driver.insert_page(DATA_GFN);

    let pml4_pa =
        Amd64::pa_from_gfn(PML4_GFN) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8;
    driver.write_pte(pml4_pa, make_pte(PDPT_GFN));

    driver.write_pte(pdpt_entry_pa(), make_large_pte(DATA_GFN));

    let new_gfn = Gfn(10);
    driver.insert_page(new_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.monitored_tables(), 2);
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change PFN of 1GB large page.
    vmi.driver()
        .write_pte(pdpt_entry_pa(), make_large_pte(new_gfn));
    ptm.mark_dirty_entry(pdpt_entry_pa(), VIEW, VCPU);
    let events = ptm.process_dirty_entries(&vmi, VCPU)?;

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    let expected_pa = Amd64::pa_from_gfn(new_gfn) + (TEST_VA.0 & 0x3fff_ffff);
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
    // Mark dirty on vCPU 0, then process on vCPU 1 — vCPU 1 should see
    // no dirty entries. Only vCPU 0's processing should produce events.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Change PT entry and mark dirty on vcpu 0.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_pte(new_data_gfn));
    let marked = ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU_0);
    assert!(marked);

    // Process on vcpu 1 — should see nothing.
    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert!(
        events.is_empty(),
        "vcpu 1 should not see vcpu 0's dirty entries"
    );
    // The page should still be paged in with the OLD mapping, since
    // vcpu 0's dirty entry hasn't been processed yet.
    assert_eq!(ptm.paged_in_entries(), 1);

    // Process on vcpu 0 — should see the change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data_gfn) + Amd64::va_offset(TEST_VA)));
    assert_eq!(ptm.paged_in_entries(), 1);

    Ok(())
}

#[test]
fn independent_dirty_entries_across_vcpus() -> Result<(), VmiError> {
    // Two VAs, each written by a different vcpu. Each vcpu should only
    // process its own dirty entry.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let va2 = Va(0x2000);
    let data2_gfn = Gfn(6);
    driver.insert_page(data2_gfn);
    let pt_entry_pa2 =
        Amd64::pa_from_gfn(PT_GFN) + Amd64::va_index_for(va2, PageTableLevel::Pt) * 8;
    driver.write_pte(pt_entry_pa2, make_pte(data2_gfn));

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

    // vcpu 0 changes VA1's PT entry.
    vmi.driver().write_pte(pt_entry_pa(), make_pte(new_data1));
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU_0);

    // vcpu 1 changes VA2's PT entry.
    vmi.driver().write_pte(pt_entry_pa2, make_pte(new_data2));
    ptm.mark_dirty_entry(pt_entry_pa2, VIEW, VCPU_1);

    // Process vcpu 1 first — should only see VA2's change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_1)?;
    assert_eq!(events.len(), 2, "vcpu 1 should see VA2 page-out + page-in");
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == ctx2));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data2) + Amd64::va_offset(va2)));

    // Process vcpu 0 — should only see VA1's change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2, "vcpu 0 should see VA1 page-out + page-in");
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(ref u) if u.ctx == test_ctx()));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(ref u)
        if u.pa == Amd64::pa_from_gfn(new_data1) + Amd64::va_offset(TEST_VA)));

    assert_eq!(ptm.paged_in_entries(), 2);

    Ok(())
}

#[test]
fn process_empty_vcpu_returns_empty() -> Result<(), VmiError> {
    // Processing a vcpu that has never had dirty entries should be a no-op.
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
    // The same entry is marked dirty by two vcpus (e.g., both singlestepped
    // on the same page table page). Each vcpu should process it independently.
    let driver = MockPtmDriver::new();
    build_full_hierarchy(&driver);

    let new_data_gfn = Gfn(10);
    driver.insert_page(new_data_gfn);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, test_ctx(), VIEW, "test")?;
    assert_eq!(ptm.paged_in_entries(), 1);

    // Both vcpus mark the same entry dirty.
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU_0);
    ptm.mark_dirty_entry(pt_entry_pa(), VIEW, VCPU_1);

    // Change the PTE.
    vmi.driver()
        .write_pte(pt_entry_pa(), make_pte(new_data_gfn));

    // vcpu 0 processes — sees the change.
    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PageTableMonitorEvent::PageOut(..)));
    assert!(matches!(events[1], PageTableMonitorEvent::PageIn(..)));

    // vcpu 1 processes — entry already updated by vcpu 0's processing,
    // so cached_pte matches current PTE: no events.
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
    // Regression test for Bug #3: walk_subtree must not overwrite cached_pte
    // on an existing entry, or it masks pending dirty changes for other VAs.
    //
    // Setup: two roots, same VA (0x1000), with a shared PT page.
    //   Root1: PML4(30) → PDPT(31) → PD(32) → PT_old(33) → DATA_1(34)
    //   Root2: PML4(40) → PDPT(41) → PD(42) → PT_shared(50) → DATA_2(51)
    //
    // Then simultaneously:
    //   1. Root1's PD entry changes to point to PT_shared (instead of PT_old)
    //   2. PT_shared's entry changes to point to new_DATA_2(52) (instead of DATA_2)
    //
    // Both entries are marked dirty. PD is processed first (higher level).
    // walk_subtree for Root1 walks into PT_shared which Root2 already monitors.
    //
    // Bug: walk_subtree overwrites cached_pte → Root2's change is masked.
    // Fix: walk_subtree preserves cached_pte → Root2's change is detected.

    let driver = MockPtmDriver::new();

    // ── Root1 hierarchy ──
    let pml4_1 = Gfn(30);
    let pdpt_1 = Gfn(31);
    let pd_1 = Gfn(32);
    let pt_old = Gfn(33);
    let data_1 = Gfn(34);
    for gfn in [pml4_1, pdpt_1, pd_1, pt_old, data_1] {
        driver.insert_page(gfn);
    }

    driver.write_pte(
        Amd64::pa_from_gfn(pml4_1) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8,
        make_pte(pdpt_1),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pdpt_1) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8,
        make_pte(pd_1),
    );
    let pd_1_entry_pa =
        Amd64::pa_from_gfn(pd_1) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8;
    driver.write_pte(pd_1_entry_pa, make_pte(pt_old));
    driver.write_pte(
        Amd64::pa_from_gfn(pt_old) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8,
        make_pte(data_1),
    );

    // ── Root2 hierarchy ──
    let pml4_2 = Gfn(40);
    let pdpt_2 = Gfn(41);
    let pd_2 = Gfn(42);
    let pt_shared = Gfn(50);
    let data_2 = Gfn(51);
    let new_data_2 = Gfn(52);
    for gfn in [pml4_2, pdpt_2, pd_2, pt_shared, new_data_2] {
        driver.insert_page(gfn);
    }

    driver.write_pte(
        Amd64::pa_from_gfn(pml4_2) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pml4) * 8,
        make_pte(pdpt_2),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pdpt_2) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pdpt) * 8,
        make_pte(pd_2),
    );
    driver.write_pte(
        Amd64::pa_from_gfn(pd_2) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pd) * 8,
        make_pte(pt_shared),
    );
    let shared_pt_entry_pa =
        Amd64::pa_from_gfn(pt_shared) + Amd64::va_index_for(TEST_VA, PageTableLevel::Pt) * 8;
    driver.write_pte(shared_pt_entry_pa, make_pte(data_2));

    let root1 = Amd64::pa_from_gfn(pml4_1);
    let root2 = Amd64::pa_from_gfn(pml4_2);
    let ctx1 = AddressContext::new(TEST_VA, root1);
    let ctx2 = AddressContext::new(TEST_VA, root2);

    let vmi = make_vmi(driver)?;
    let mut ptm = PageTableMonitor::<MockPtmDriver>::new();

    ptm.monitor(&vmi, ctx1, VIEW, "root1")?;
    ptm.monitor(&vmi, ctx2, VIEW, "root2")?;
    assert_eq!(ptm.paged_in_entries(), 2);

    // ── Simultaneous changes ──
    // 1. Root1's PD entry now points to PT_shared.
    vmi.driver().write_pte(pd_1_entry_pa, make_pte(pt_shared));
    // 2. PT_shared's entry now points to new_DATA_2.
    vmi.driver()
        .write_pte(shared_pt_entry_pa, make_pte(new_data_2));

    // Mark both dirty on the same vcpu.
    ptm.mark_dirty_entry(pd_1_entry_pa, VIEW, VCPU_0);
    ptm.mark_dirty_entry(shared_pt_entry_pa, VIEW, VCPU_0);

    let events = ptm.process_dirty_entries(&vmi, VCPU_0)?;

    // Root2 MUST get a PageOut for the old DATA_2 mapping.
    // With Bug #3, walk_subtree overwrites cached_pte and this event is lost.
    let root2_page_outs: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageOut(u) if u.ctx == ctx2))
        .collect();
    assert!(
        !root2_page_outs.is_empty(),
        "Root2 must get PageOut when its PT entry PFN changes"
    );

    // Root2 must also get a PageIn for new_DATA_2.
    let root2_page_ins: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, PageTableMonitorEvent::PageIn(u) if u.ctx == ctx2))
        .collect();
    assert!(
        !root2_page_ins.is_empty(),
        "Root2 must get PageIn for new_DATA_2"
    );

    Ok(())
}
