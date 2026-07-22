//! In-memory `VmiDriver` shared by the `vmi-utils` test suites.
//!
//! Models guest physical pages, per-view GFN remappings, and memory-access
//! protection, records every operation for assertions, and can inject a fault
//! into any single driver call. Used by the interceptor, bpm, and ptm tests.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use vmi_arch_amd64::{Amd64, Interrupt, PageTableEntry};
use vmi_core::{
    Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, VcpuId, View, VmiDriver,
    VmiError, VmiInfo, VmiMappedPage, VmiQueryProtection, VmiRead, VmiSetProtection,
    VmiViewControl, VmiVmControl, VmiWrite,
};

///////////////////////////////////////////////////////////////////////////////
// Mock Driver
///////////////////////////////////////////////////////////////////////////////

/// A single driver operation recorded by the mock, used to assert the exact
/// sequence of hypervisor interactions a component performs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    /// `read_page(gfn)`.
    ReadPage(Gfn),

    /// `write_page(gfn, offset, content)`, recording only the length.
    WritePage { gfn: Gfn, offset: u64, len: usize },

    /// `allocate_gfn()` returning the given frame.
    AllocateGfn(Gfn),

    /// `change_view_gfn(view, old, new)`.
    ChangeViewGfn { view: View, old: Gfn, new: Gfn },

    /// `reset_view_gfn(view, gfn)`.
    ResetViewGfn { view: View, gfn: Gfn },

    /// `set_memory_access(gfn, view, access)`.
    SetMemoryAccess {
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    },
}

/// A driver operation that can be armed to fail on a chosen invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    /// `read_page`.
    ReadPage,

    /// `write_page`.
    WritePage,

    /// `allocate_gfn`.
    AllocateGfn,

    /// `change_view_gfn`.
    ChangeView,

    /// `reset_view_gfn`.
    ResetView,

    /// `set_memory_access`.
    SetMemoryAccess,
}

/// Base frame number for shadow pages allocated by the mock. Chosen well above
/// the low frames the tests use for guest and page-table pages.
const SHADOW_BASE: u64 = 0x1000;

/// Builds a present 4 KiB page-table entry pointing at `gfn`.
pub(crate) fn make_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | 1)
}

/// Builds a present large (PS bit) page-table entry pointing at `gfn`.
pub(crate) fn make_large_pte(gfn: Gfn) -> PageTableEntry {
    PageTableEntry((gfn.0 << 12) | (1 << 7) | 1)
}

/// Builds a not-present page-table entry.
pub(crate) fn make_not_present_pte() -> PageTableEntry {
    PageTableEntry(0)
}

/// In-memory stand-in for a VMI driver.
pub(crate) struct MockDriver {
    /// Guest physical pages, each 4 KiB, indexed by frame number.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,

    /// Active per-view remappings, mapping `(view, original)` to its shadow.
    views: RefCell<HashMap<(View, Gfn), Gfn>>,

    /// Per-`(view, gfn)` memory-access protection.
    access: RefCell<HashMap<(View, Gfn), MemoryAccess>>,

    /// Ordered log of every recorded operation.
    log: RefCell<Vec<Call>>,

    /// Next frame number handed out by `allocate_gfn`.
    next_gfn: Cell<u64>,

    /// Next identifier handed out by `create_view`.
    next_view: Cell<u16>,

    /// Per-operation invocation counters.
    counters: RefCell<HashMap<Op, usize>>,

    /// Armed faults, mapping an operation to the 1-based invocation to fail.
    faults: RefCell<HashMap<Op, usize>>,
}

impl MockDriver {
    /// Creates an empty driver with no pages and no armed faults.
    pub(crate) fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            views: RefCell::new(HashMap::new()),
            access: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            next_gfn: Cell::new(SHADOW_BASE),
            next_view: Cell::new(1),
            counters: RefCell::new(HashMap::new()),
            faults: RefCell::new(HashMap::new()),
        }
    }

    /// Inserts a 4 KiB page at `gfn` filled with `byte`.
    pub(crate) fn fill_page(&self, gfn: Gfn, byte: u8) {
        self.pages.borrow_mut().insert(gfn, vec![byte; 4096]);
    }

    /// Inserts a blank 4 KiB page at `gfn`.
    pub(crate) fn insert_page(&self, gfn: Gfn) {
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
    }

    /// Overwrites bytes at `offset` within the page at `gfn`, creating a blank
    /// page first if none exists.
    pub(crate) fn write_original(&self, gfn: Gfn, offset: usize, bytes: &[u8]) {
        let mut pages = self.pages.borrow_mut();
        let page = pages.entry(gfn).or_insert_with(|| vec![0u8; 4096]);
        page[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Returns the byte at `offset` within the page at `gfn`.
    pub(crate) fn byte(&self, gfn: Gfn, offset: usize) -> u8 {
        self.pages.borrow().get(&gfn).expect("page exists")[offset]
    }

    /// Returns a copy of the whole page at `gfn`.
    pub(crate) fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.pages.borrow().get(&gfn).cloned().expect("page exists")
    }

    /// Returns the shadow frame currently mapped for `(view, gfn)`, if any.
    pub(crate) fn view_target(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.views.borrow().get(&(view, gfn)).copied()
    }

    /// Returns the memory access currently configured for `(view, gfn)`,
    /// defaulting to `RWX` when none was set.
    pub(crate) fn access(&self, gfn: Gfn, view: View) -> MemoryAccess {
        self.access
            .borrow()
            .get(&(view, gfn))
            .copied()
            .unwrap_or(MemoryAccess::RWX)
    }

    /// Seeds the protection for `(view, gfn)` without recording a call.
    pub(crate) fn set_initial_access(&self, gfn: Gfn, view: View, access: MemoryAccess) {
        self.access.borrow_mut().insert((view, gfn), access);
    }

    /// Writes a page table entry at the given physical address.
    pub(crate) fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        let gfn = Amd64::gfn_from_pa(pa);
        let offset = Amd64::pa_offset(pa) as usize;
        let mut pages = self.pages.borrow_mut();
        let page = pages.get_mut(&gfn).expect("page for pte");
        page[offset..offset + 8].copy_from_slice(&pte.0.to_le_bytes());
    }

    /// Returns a copy of the recorded operation log.
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.log.borrow().clone()
    }

    /// Clears the recorded operation log.
    pub(crate) fn clear_log(&self) {
        self.log.borrow_mut().clear();
    }

    /// Counts recorded operations matching `predicate`.
    pub(crate) fn count(&self, predicate: impl Fn(&Call) -> bool) -> usize {
        self.log.borrow().iter().filter(|c| predicate(c)).count()
    }

    /// Arms operation `op` to fail on its `nth` (1-based) invocation.
    pub(crate) fn arm_fault(&self, op: Op, nth: usize) {
        self.faults.borrow_mut().insert(op, nth);
    }

    /// Increments the invocation counter for `op` and returns an error if this
    /// invocation is armed to fail.
    fn maybe_fail(&self, op: Op) -> Result<(), VmiError> {
        let mut counters = self.counters.borrow_mut();
        let count = counters.entry(op).or_insert(0);
        *count += 1;
        let count = *count;

        if self.faults.borrow().get(&op) == Some(&count) {
            return Err(VmiError::Other("injected fault"));
        }

        Ok(())
    }
}

impl VmiDriver for MockDriver {
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

impl VmiRead for MockDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.maybe_fail(Op::ReadPage)?;
        self.log.borrow_mut().push(Call::ReadPage(gfn));

        let pages = self.pages.borrow();
        let page = pages.get(&gfn).ok_or(VmiError::Other("read: no page"))?;
        Ok(VmiMappedPage::new(page.clone()))
    }
}

impl VmiWrite for MockDriver {
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        self.maybe_fail(Op::WritePage)?;
        self.log.borrow_mut().push(Call::WritePage {
            gfn,
            offset,
            len: content.len(),
        });

        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&gfn)
            .ok_or(VmiError::Other("write: no page"))?;

        let start = offset as usize;
        let end = start + content.len();
        assert!(end <= page.len(), "write past end of page");
        page[start..end].copy_from_slice(content);

        Ok(VmiMappedPage::new(page.clone()))
    }
}

impl VmiVmControl for MockDriver {
    fn pause(&self) -> Result<(), VmiError> {
        Ok(())
    }

    fn resume(&self) -> Result<(), VmiError> {
        Ok(())
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        self.maybe_fail(Op::AllocateGfn)?;

        let gfn = Gfn(self.next_gfn.get());
        self.next_gfn.set(gfn.0 + 1);

        // A freshly allocated frame is zeroed and immediately readable/writable.
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
        self.log.borrow_mut().push(Call::AllocateGfn(gfn));
        Ok(gfn)
    }

    fn allocate_gfn_at(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.pages.borrow_mut().insert(gfn, vec![0u8; 4096]);
        Ok(())
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.pages.borrow_mut().remove(&gfn);
        Ok(())
    }

    fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: Interrupt) -> Result<(), VmiError> {
        Ok(())
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Ok(())
    }
}

impl VmiViewControl for MockDriver {
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
        let id = self.next_view.get();
        self.next_view.set(id + 1);
        Ok(View(id))
    }

    fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
        Ok(())
    }

    fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
        Ok(())
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        self.maybe_fail(Op::ChangeView)?;
        self.log.borrow_mut().push(Call::ChangeViewGfn {
            view,
            old: old_gfn,
            new: new_gfn,
        });
        self.views.borrow_mut().insert((view, old_gfn), new_gfn);
        Ok(())
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.maybe_fail(Op::ResetView)?;
        self.log.borrow_mut().push(Call::ResetViewGfn { view, gfn });
        self.views.borrow_mut().remove(&(view, gfn));
        Ok(())
    }
}

impl VmiQueryProtection for MockDriver {
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.access(gfn, view))
    }

    fn memory_access_with_options(
        &self,
        _gfn: Gfn,
        _view: View,
    ) -> Result<(MemoryAccess, MemoryAccessOptions), VmiError> {
        Err(VmiError::NotSupported)
    }
}

impl VmiSetProtection for MockDriver {
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        self.maybe_fail(Op::SetMemoryAccess)?;
        self.log
            .borrow_mut()
            .push(Call::SetMemoryAccess { gfn, view, access });
        self.access.borrow_mut().insert((view, gfn), access);
        Ok(())
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        _options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        self.set_memory_access(gfn, view, access)
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use vmi_arch_amd64::Amd64;
    use vmi_core::{
        Architecture as _, Gfn, MemoryAccess, Pa, View, VmiError, VmiQueryProtection, VmiRead,
        VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    };

    use super::{Call, MockDriver, Op, make_large_pte, make_not_present_pte, make_pte};

    #[test]
    fn read_page_returns_seeded_bytes() {
        let driver = MockDriver::new();
        driver.fill_page(Gfn(0x10), 0xab);

        let page = driver.read_page(Gfn(0x10)).expect("read");

        assert_eq!(page[0], 0xab);
        assert_eq!(page[4095], 0xab);
    }

    #[test]
    fn read_page_missing_errors() {
        let driver = MockDriver::new();

        assert!(matches!(
            driver.read_page(Gfn(0x99)),
            Err(VmiError::Other("read: no page"))
        ));
    }

    #[test]
    fn read_page_is_recorded() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x10));

        driver.read_page(Gfn(0x10)).expect("read");

        assert_eq!(driver.calls(), vec![Call::ReadPage(Gfn(0x10))]);
        assert_eq!(driver.count(|c| matches!(c, Call::ReadPage(_))), 1);
    }

    #[test]
    fn armed_fault_fires_on_the_nth_call_only_and_is_not_recorded() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x10));
        driver.arm_fault(Op::ReadPage, 2);

        driver.read_page(Gfn(0x10)).expect("first read ok");
        assert!(matches!(
            driver.read_page(Gfn(0x10)),
            Err(VmiError::Other("injected fault"))
        ));
        driver.read_page(Gfn(0x10)).expect("third read ok");

        // The faulted call is not recorded: only calls 1 and 3 appear.
        assert_eq!(driver.count(|c| matches!(c, Call::ReadPage(_))), 2);
    }

    #[test]
    fn clear_log_empties_the_record() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x10));
        driver.read_page(Gfn(0x10)).expect("read");

        driver.clear_log();

        assert!(driver.calls().is_empty());
    }

    #[test]
    fn write_page_round_trips_and_is_recorded() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x10));

        driver.write_page(Gfn(0x10), 4, &[1, 2, 3]).expect("write");

        assert_eq!(driver.byte(Gfn(0x10), 4), 1);
        assert_eq!(driver.byte(Gfn(0x10), 6), 3);
        assert_eq!(driver.page(Gfn(0x10))[5], 2);
        assert_eq!(
            driver.calls(),
            vec![Call::WritePage {
                gfn: Gfn(0x10),
                offset: 4,
                len: 3
            }]
        );
    }

    #[test]
    fn write_original_creates_and_overwrites_without_recording() {
        let driver = MockDriver::new();

        // Creates a blank page on first use, leaving untouched bytes zero.
        driver.write_original(Gfn(0x10), 2, &[0xaa, 0xbb]);
        assert_eq!(driver.byte(Gfn(0x10), 2), 0xaa);
        assert_eq!(driver.byte(Gfn(0x10), 3), 0xbb);
        assert_eq!(driver.byte(Gfn(0x10), 0), 0);

        // Overwrites in place and does not record a driver call.
        driver.write_original(Gfn(0x10), 2, &[0xcc]);
        assert_eq!(driver.byte(Gfn(0x10), 2), 0xcc);
        assert!(driver.calls().is_empty());
    }

    #[test]
    fn write_page_missing_errors() {
        let driver = MockDriver::new();

        // `VmiMappedPage` is not `Debug`; assert on the `Result` directly.
        assert!(matches!(
            driver.write_page(Gfn(0x99), 0, &[1]),
            Err(VmiError::Other("write: no page"))
        ));
    }

    #[test]
    #[should_panic(expected = "write past end of page")]
    fn write_page_past_end_panics() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x10));

        let _ = driver.write_page(Gfn(0x10), 4095, &[1, 2]);
    }

    #[test]
    fn allocate_gfn_hands_out_increasing_zeroed_frames() {
        let driver = MockDriver::new();

        let first = driver.allocate_gfn().expect("alloc");
        let second = driver.allocate_gfn().expect("alloc");

        assert_eq!(first, Gfn(0x1000));
        assert_eq!(second, Gfn(0x1001));
        assert_eq!(
            driver.calls(),
            vec![Call::AllocateGfn(first), Call::AllocateGfn(second)]
        );

        // Freshly allocated frames are zeroed and immediately readable/writable.
        assert_eq!(driver.byte(first, 0), 0);
        driver.write_page(first, 0, &[7]).expect("write fresh");
        assert_eq!(driver.byte(first, 0), 7);
    }

    #[test]
    fn allocate_gfn_at_and_free_gfn() {
        let driver = MockDriver::new();

        driver.allocate_gfn_at(Gfn(0x55)).expect("alloc at");
        assert_eq!(driver.byte(Gfn(0x55), 0), 0);

        driver.free_gfn(Gfn(0x55)).expect("free");
        // After free the page is gone; reading it errors.
        assert!(driver.read_page(Gfn(0x55)).is_err());
    }

    #[test]
    fn allocate_gfn_can_be_faulted() {
        let driver = MockDriver::new();
        driver.arm_fault(Op::AllocateGfn, 1);

        assert!(driver.allocate_gfn().is_err());
    }

    #[test]
    fn change_and_reset_view_gfn_track_remapping() {
        let driver = MockDriver::new();

        driver
            .change_view_gfn(View(1), Gfn(0x10), Gfn(0x20))
            .expect("change");
        assert_eq!(driver.view_target(View(1), Gfn(0x10)), Some(Gfn(0x20)));

        driver.reset_view_gfn(View(1), Gfn(0x10)).expect("reset");
        assert_eq!(driver.view_target(View(1), Gfn(0x10)), None);

        assert_eq!(
            driver.calls(),
            vec![
                Call::ChangeViewGfn {
                    view: View(1),
                    old: Gfn(0x10),
                    new: Gfn(0x20)
                },
                Call::ResetViewGfn {
                    view: View(1),
                    gfn: Gfn(0x10)
                },
            ]
        );
    }

    #[test]
    fn create_view_hands_out_increasing_ids() {
        let driver = MockDriver::new();

        assert_eq!(driver.default_view(), View(0));
        assert_eq!(
            driver.create_view(MemoryAccess::RWX).expect("create"),
            View(1)
        );
        assert_eq!(
            driver.create_view(MemoryAccess::RWX).expect("create"),
            View(2)
        );
    }

    #[test]
    fn change_view_gfn_can_be_faulted() {
        let driver = MockDriver::new();
        driver.arm_fault(Op::ChangeView, 1);

        assert!(
            driver
                .change_view_gfn(View(1), Gfn(0x10), Gfn(0x20))
                .is_err()
        );
    }

    #[test]
    fn access_defaults_to_rwx() {
        let driver = MockDriver::new();

        assert_eq!(driver.access(Gfn(0x10), View(0)), MemoryAccess::RWX);
        assert_eq!(
            driver.memory_access(Gfn(0x10), View(0)).expect("query"),
            MemoryAccess::RWX
        );
    }

    #[test]
    fn set_memory_access_round_trips_and_is_recorded() {
        let driver = MockDriver::new();

        driver
            .set_memory_access(Gfn(0x10), View(0), MemoryAccess::R)
            .expect("set");

        assert_eq!(driver.access(Gfn(0x10), View(0)), MemoryAccess::R);
        assert_eq!(
            driver.memory_access(Gfn(0x10), View(0)).expect("query"),
            MemoryAccess::R
        );
        assert_eq!(
            driver.calls(),
            vec![Call::SetMemoryAccess {
                gfn: Gfn(0x10),
                view: View(0),
                access: MemoryAccess::R
            }]
        );
    }

    #[test]
    fn set_initial_access_seeds_without_recording() {
        let driver = MockDriver::new();

        driver.set_initial_access(Gfn(0x10), View(0), MemoryAccess::RW);

        assert_eq!(driver.access(Gfn(0x10), View(0)), MemoryAccess::RW);
        assert!(driver.calls().is_empty());
    }

    #[test]
    fn set_memory_access_can_be_faulted() {
        let driver = MockDriver::new();
        driver.arm_fault(Op::SetMemoryAccess, 1);

        assert!(
            driver
                .set_memory_access(Gfn(0x10), View(0), MemoryAccess::R)
                .is_err()
        );
        // A faulted set leaves the protection unchanged.
        assert_eq!(driver.access(Gfn(0x10), View(0)), MemoryAccess::RWX);
    }

    #[test]
    fn pte_builders_produce_expected_bits() {
        // Present 4 KiB PTE: present bit set, no large bit, frame in bits 12+.
        assert_eq!(make_pte(Gfn(0x20)).0, (0x20 << 12) | 1);
        // Large PTE: present + PS (bit 7).
        assert_eq!(make_large_pte(Gfn(0x20)).0, (0x20 << 12) | (1 << 7) | 1);
        // Not-present PTE is all zero.
        assert_eq!(make_not_present_pte().0, 0);
    }

    #[test]
    fn write_pte_round_trips_at_the_right_offset() {
        let driver = MockDriver::new();
        driver.insert_page(Gfn(0x30));
        // Byte offset 0x40 within frame 0x30.
        let pa = Pa((0x30 << 12) | 0x40);

        driver.write_pte(pa, make_pte(Gfn(0x77)));

        // The 8 little-endian bytes at that offset decode to the PTE value.
        let mut bytes = [0u8; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = driver.byte(Gfn(0x30), 0x40 + i);
        }
        assert_eq!(u64::from_le_bytes(bytes), make_pte(Gfn(0x77)).0);
        // Sanity: the helper places it in the frame `gfn_from_pa(pa)` reports.
        assert_eq!(Amd64::gfn_from_pa(pa), Gfn(0x30));
    }
}
