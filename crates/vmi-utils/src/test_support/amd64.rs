use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use vmi_arch_amd64::{Amd64, PageTableEntry};
use vmi_core::{
    Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, Pa, View, VmiError, VmiInfo,
    VmiMappedPage,
};

/// One low-level driver operation that should fail when next attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverFault {
    /// Fails GFN allocation.
    Allocate,

    /// Fails a read from the given GFN.
    Read(Gfn),

    /// Fails a write at the given GFN and byte offset.
    Write(Gfn, u64),

    /// Fails the given view mapping change.
    Change(View, Gfn, Gfn),

    /// Fails the given view mapping reset.
    Reset(View, Gfn),
}

/// One observable low-level driver call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverCall {
    /// Allocates the given GFN.
    Allocate(Gfn),

    /// Frees the given GFN.
    Free(Gfn),

    /// Reads the given GFN.
    Read(Gfn),

    /// Writes the given GFN, byte offset, and byte count.
    Write(Gfn, u64, usize),

    /// Changes a view mapping from one GFN to another.
    Change(View, Gfn, Gfn),

    /// Resets a view mapping for the given GFN.
    Reset(View, Gfn),
}

/// Models the reusable AMD64 state behind component-specific test drivers.
pub(crate) struct Amd64TestVm {
    /// Guest physical pages keyed by GFN.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,

    /// Explicit shadow mappings keyed by view and original GFN.
    mappings: RefCell<HashMap<(View, Gfn), Gfn>>,

    /// Memory permissions and options keyed by view and GFN.
    access: RefCell<HashMap<(View, Gfn), (MemoryAccess, MemoryAccessOptions)>>,

    /// GFN returned by the next successful allocation.
    next_gfn: Cell<Gfn>,

    /// Low-level operation that should fail once.
    fault: Cell<Option<DriverFault>>,

    /// Whether low-level operations should be retained for assertions.
    record_calls: bool,

    /// Calls attempted against the state engine in chronological order.
    calls: RefCell<Vec<DriverCall>>,
}

impl Amd64TestVm {
    /// Creates empty state with low-level call recording enabled.
    pub(crate) fn new(first_allocatable_gfn: Gfn) -> Self {
        Self::with_call_recording(first_allocatable_gfn, true)
    }

    /// Creates empty state without retaining low-level calls.
    pub(crate) fn without_call_recording(first_allocatable_gfn: Gfn) -> Self {
        Self::with_call_recording(first_allocatable_gfn, false)
    }

    /// Returns deterministic AMD64 VM metadata.
    pub(crate) fn info(&self) -> VmiInfo {
        VmiInfo {
            page_size: Amd64::PAGE_SIZE,
            page_shift: Amd64::PAGE_SHIFT,
            max_gfn: Gfn(0xffff),
            vcpus: 1,
        }
    }

    /// Adds an initialized guest page.
    pub(crate) fn insert_page(&self, gfn: Gfn, content: Vec<u8>) {
        assert_eq!(
            content.len(),
            Amd64::PAGE_SIZE as usize,
            "invalid page size at {gfn:?}"
        );
        let previous = self.pages.borrow_mut().insert(gfn, content);
        assert!(previous.is_none(), "page already exists at {gfn:?}");
    }

    /// Adds a zero-filled guest page.
    pub(crate) fn insert_zeroed_page(&self, gfn: Gfn) {
        self.insert_page(gfn, vec![0; Amd64::PAGE_SIZE as usize]);
    }

    /// Replaces an existing guest page.
    pub(crate) fn replace_page(&self, gfn: Gfn, content: Vec<u8>) {
        assert_eq!(
            content.len(),
            Amd64::PAGE_SIZE as usize,
            "invalid page size at {gfn:?}"
        );
        let previous = self.pages.borrow_mut().insert(gfn, content);
        assert!(previous.is_some(), "no page at {gfn:?}");
    }

    /// Returns a copy of a guest page.
    pub(crate) fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.pages
            .borrow()
            .get(&gfn)
            .unwrap_or_else(|| panic!("no page at {gfn:?}"))
            .clone()
    }

    /// Returns whether a guest page exists.
    pub(crate) fn has_page(&self, gfn: Gfn) -> bool {
        self.pages.borrow().contains_key(&gfn)
    }

    /// Replaces bytes without recording a low-level driver operation.
    pub(crate) fn set_bytes(&self, gfn: Gfn, offset: u64, content: &[u8]) {
        self.replace_bytes(gfn, offset, content)
            .unwrap_or_else(|err| panic!("failed to set bytes at {gfn:?}+{offset:#x}: {err}"));
    }

    /// Writes an AMD64 page-table entry without recording a driver operation.
    pub(crate) fn write_pte(&self, pa: Pa, pte: PageTableEntry) {
        let gfn = Amd64::gfn_from_pa(pa);
        let offset = Amd64::pa_offset(pa);
        self.set_bytes(gfn, offset, &pte.0.to_le_bytes());
    }

    /// Returns the explicit mapping for a view and original GFN.
    pub(crate) fn mapping(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.mappings.borrow().get(&(view, gfn)).copied()
    }

    /// Returns memory permissions, defaulting to full access.
    pub(crate) fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.memory_access_entry(gfn, view).0)
    }

    /// Returns memory permissions and their options.
    pub(crate) fn memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
    ) -> Result<(MemoryAccess, MemoryAccessOptions), VmiError> {
        Ok(self.memory_access_entry(gfn, view))
    }

    /// Sets memory permissions with default options.
    pub(crate) fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        self.store_memory_access(gfn, view, access, MemoryAccessOptions::default());
        Ok(())
    }

    /// Sets memory permissions and their options.
    pub(crate) fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        self.store_memory_access(gfn, view, access, options);
        Ok(())
    }

    /// Configures one exactly matching low-level operation to fail.
    pub(crate) fn fail_on(&self, fault: DriverFault) {
        assert!(self.fault.replace(Some(fault)).is_none());
    }

    /// Returns the chronological low-level call history.
    pub(crate) fn calls(&self) -> Vec<DriverCall> {
        self.calls.borrow().clone()
    }

    /// Clears the low-level call history.
    pub(crate) fn clear_calls(&self) {
        self.calls.borrow_mut().clear();
    }

    /// Reads a guest page as a low-level driver operation.
    pub(crate) fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.record_call(DriverCall::Read(gfn));
        if self.take_fault(DriverFault::Read(gfn)) {
            return Err(VmiError::Other("injected read failure"));
        }

        let page = self
            .pages
            .borrow()
            .get(&gfn)
            .ok_or(VmiError::Other("page not found"))?
            .clone();
        Ok(VmiMappedPage::new(page))
    }

    /// Writes guest bytes as a low-level driver operation.
    pub(crate) fn write_page(
        &self,
        gfn: Gfn,
        offset: u64,
        content: &[u8],
    ) -> Result<VmiMappedPage, VmiError> {
        self.record_call(DriverCall::Write(gfn, offset, content.len()));
        if self.take_fault(DriverFault::Write(gfn, offset)) {
            return Err(VmiError::Other("injected write failure"));
        }

        let page = self.replace_bytes(gfn, offset, content)?;
        Ok(VmiMappedPage::new(page))
    }

    /// Changes a view mapping as a low-level driver operation.
    pub(crate) fn change_view_gfn(
        &self,
        view: View,
        old_gfn: Gfn,
        new_gfn: Gfn,
    ) -> Result<(), VmiError> {
        self.record_call(DriverCall::Change(view, old_gfn, new_gfn));
        if self.take_fault(DriverFault::Change(view, old_gfn, new_gfn)) {
            return Err(VmiError::Other("injected view-change failure"));
        }

        self.mappings.borrow_mut().insert((view, old_gfn), new_gfn);
        Ok(())
    }

    /// Resets a view mapping as a low-level driver operation.
    pub(crate) fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.record_call(DriverCall::Reset(view, gfn));
        if self.take_fault(DriverFault::Reset(view, gfn)) {
            return Err(VmiError::Other("injected view-reset failure"));
        }

        self.mappings.borrow_mut().remove(&(view, gfn));
        Ok(())
    }

    /// Allocates a zero-filled GFN as a low-level driver operation.
    pub(crate) fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        if self.take_fault(DriverFault::Allocate) {
            return Err(VmiError::Other("injected allocation failure"));
        }

        let gfn = self.next_gfn.get();
        self.next_gfn.set(Gfn(gfn.0 + 1));
        self.insert_zeroed_page(gfn);
        self.record_call(DriverCall::Allocate(gfn));
        Ok(gfn)
    }

    /// Frees a GFN as a low-level driver operation.
    pub(crate) fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.record_call(DriverCall::Free(gfn));
        self.pages
            .borrow_mut()
            .remove(&gfn)
            .ok_or(VmiError::Other("page not found"))?;
        Ok(())
    }

    /// Creates state with the requested call-recording behavior.
    fn with_call_recording(first_allocatable_gfn: Gfn, record_calls: bool) -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            mappings: RefCell::new(HashMap::new()),
            access: RefCell::new(HashMap::new()),
            next_gfn: Cell::new(first_allocatable_gfn),
            fault: Cell::new(None),
            record_calls,
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Retains a low-level call when recording is enabled.
    fn record_call(&self, call: DriverCall) {
        if self.record_calls {
            self.calls.borrow_mut().push(call);
        }
    }

    /// Returns stored memory permissions and options.
    fn memory_access_entry(&self, gfn: Gfn, view: View) -> (MemoryAccess, MemoryAccessOptions) {
        self.access
            .borrow()
            .get(&(view, gfn))
            .copied()
            .unwrap_or((MemoryAccess::RWX, MemoryAccessOptions::default()))
    }

    /// Stores memory permissions and options.
    fn store_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) {
        self.access
            .borrow_mut()
            .insert((view, gfn), (access, options));
    }

    /// Replaces bytes and returns a copy of the resulting page.
    fn replace_bytes(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<Vec<u8>, VmiError> {
        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&gfn)
            .ok_or(VmiError::Other("page not found"))?;
        let offset = usize::try_from(offset).map_err(|_| VmiError::OutOfBounds)?;
        let end = offset
            .checked_add(content.len())
            .ok_or(VmiError::OutOfBounds)?;
        let destination = page.get_mut(offset..end).ok_or(VmiError::OutOfBounds)?;
        destination.copy_from_slice(content);
        Ok(page.clone())
    }

    /// Consumes and reports an exactly matching configured failure.
    fn take_fault(&self, actual: DriverFault) -> bool {
        if self.fault.get() == Some(actual) {
            self.fault.set(None);
            true
        }
        else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use vmi_arch_amd64::{Amd64, PageTableEntry};
    use vmi_core::{Architecture as _, Gfn, MemoryAccess, MemoryAccessOptions, View, VmiError};

    use super::{Amd64TestVm, DriverCall, DriverFault};

    /// First GFN returned by the test allocator.
    const FIRST_ALLOCATABLE_GFN: Gfn = Gfn(0x1000);

    /// Original page used by direct state tests.
    const ORIGINAL_GFN: Gfn = Gfn(0x10);

    /// Secondary page used to verify exact fault matching.
    const OTHER_GFN: Gfn = Gfn(0x20);

    /// View used by direct state tests.
    const VIEW: View = View(7);

    /// Creates a fresh state engine with deterministic allocation.
    fn test_vm() -> Amd64TestVm {
        Amd64TestVm::new(FIRST_ALLOCATABLE_GFN)
    }

    /// Creates one page filled with a repeated byte.
    fn page_content(value: u8) -> Vec<u8> {
        vec![value; Amd64::PAGE_SIZE as usize]
    }

    /// Verifies page setup, inspection, and unrecorded fixture writes.
    #[test]
    fn page_setup_and_inspection_are_deterministic() {
        let vm = test_vm();
        vm.insert_page(ORIGINAL_GFN, page_content(0x11));
        vm.insert_zeroed_page(OTHER_GFN);

        assert!(vm.has_page(ORIGINAL_GFN));
        assert_eq!(vm.page(ORIGINAL_GFN), page_content(0x11));
        assert_eq!(vm.page(OTHER_GFN), page_content(0));

        vm.set_bytes(ORIGINAL_GFN, 2, &[0xaa, 0xbb]);
        let mut expected = page_content(0x11);
        expected[2..4].copy_from_slice(&[0xaa, 0xbb]);
        assert_eq!(vm.page(ORIGINAL_GFN), expected);

        vm.replace_page(ORIGINAL_GFN, page_content(0x22));
        assert_eq!(vm.page(ORIGINAL_GFN), page_content(0x22));
        assert!(vm.calls().is_empty());
    }

    /// Verifies page-table setup writes use the physical page offset.
    #[test]
    fn page_table_entries_are_written_in_little_endian_order() {
        let vm = test_vm();
        vm.insert_zeroed_page(ORIGINAL_GFN);
        let pte = PageTableEntry(0x1234_5678_9abc_def1);
        let pa = Amd64::pa_from_gfn(ORIGINAL_GFN) + 0x28;

        vm.write_pte(pa, pte);

        assert_eq!(&vm.page(ORIGINAL_GFN)[0x28..0x30], &pte.0.to_le_bytes());
        assert!(vm.calls().is_empty());
    }

    /// Verifies low-level writes are checked and return the updated page.
    #[test]
    fn driver_writes_check_bounds_without_partial_mutation() -> Result<(), VmiError> {
        let vm = test_vm();
        vm.insert_zeroed_page(ORIGINAL_GFN);

        let mapped = vm.write_page(ORIGINAL_GFN, 4, &[1, 2, 3])?;
        assert_eq!(&mapped.as_ref()[4..7], &[1, 2, 3]);
        let before_failure = vm.page(ORIGINAL_GFN);

        let result = vm.write_page(ORIGINAL_GFN, Amd64::PAGE_SIZE - 1, &[4, 5]);
        assert!(matches!(result, Err(VmiError::OutOfBounds)));
        assert_eq!(vm.page(ORIGINAL_GFN), before_failure);
        assert_eq!(
            vm.calls(),
            vec![
                DriverCall::Write(ORIGINAL_GFN, 4, 3),
                DriverCall::Write(ORIGINAL_GFN, Amd64::PAGE_SIZE - 1, 2),
            ]
        );

        Ok(())
    }

    /// Verifies missing pages report driver errors for reads and writes.
    #[test]
    fn missing_pages_return_errors_after_recording_calls() {
        let vm = test_vm();

        assert!(matches!(
            vm.read_page(ORIGINAL_GFN),
            Err(VmiError::Other("page not found"))
        ));
        assert!(matches!(
            vm.write_page(ORIGINAL_GFN, 0, &[1]),
            Err(VmiError::Other("page not found"))
        ));
        assert_eq!(
            vm.calls(),
            vec![
                DriverCall::Read(ORIGINAL_GFN),
                DriverCall::Write(ORIGINAL_GFN, 0, 1),
            ]
        );
    }

    /// Verifies permissions preserve option-bearing updates and defaults.
    #[test]
    fn memory_permissions_are_isolated_by_view_and_gfn() -> Result<(), VmiError> {
        let vm = test_vm();
        let options = MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES;

        assert_eq!(vm.memory_access(ORIGINAL_GFN, VIEW)?, MemoryAccess::RWX);
        assert_eq!(
            vm.memory_access_with_options(ORIGINAL_GFN, VIEW)?,
            (MemoryAccess::RWX, MemoryAccessOptions::default())
        );

        vm.set_memory_access_with_options(ORIGINAL_GFN, VIEW, MemoryAccess::RX, options)?;
        vm.set_memory_access(OTHER_GFN, VIEW, MemoryAccess::R)?;

        assert_eq!(
            vm.memory_access_with_options(ORIGINAL_GFN, VIEW)?,
            (MemoryAccess::RX, options)
        );
        assert_eq!(vm.memory_access(OTHER_GFN, VIEW)?, MemoryAccess::R);
        assert_eq!(
            vm.memory_access(ORIGINAL_GFN, View(VIEW.0 + 1))?,
            MemoryAccess::RWX
        );

        Ok(())
    }

    /// Verifies view mappings change and reset with chronological calls.
    #[test]
    fn view_mappings_are_explicit_and_recorded() -> Result<(), VmiError> {
        let vm = test_vm();

        assert_eq!(vm.mapping(VIEW, ORIGINAL_GFN), None);
        vm.change_view_gfn(VIEW, ORIGINAL_GFN, OTHER_GFN)?;
        assert_eq!(vm.mapping(VIEW, ORIGINAL_GFN), Some(OTHER_GFN));
        vm.reset_view_gfn(VIEW, ORIGINAL_GFN)?;
        assert_eq!(vm.mapping(VIEW, ORIGINAL_GFN), None);
        assert_eq!(
            vm.calls(),
            vec![
                DriverCall::Change(VIEW, ORIGINAL_GFN, OTHER_GFN),
                DriverCall::Reset(VIEW, ORIGINAL_GFN),
            ]
        );

        Ok(())
    }

    /// Verifies allocation and freeing are deterministic and observable.
    #[test]
    fn allocation_and_freeing_update_pages_and_calls() -> Result<(), VmiError> {
        let vm = test_vm();

        let first = vm.allocate_gfn()?;
        let second = vm.allocate_gfn()?;
        assert_eq!(first, FIRST_ALLOCATABLE_GFN);
        assert_eq!(second, Gfn(FIRST_ALLOCATABLE_GFN.0 + 1));
        assert_eq!(vm.page(first), page_content(0));
        assert_eq!(vm.page(second), page_content(0));

        vm.free_gfn(first)?;
        assert!(!vm.has_page(first));
        assert!(vm.has_page(second));
        assert_eq!(
            vm.calls(),
            vec![
                DriverCall::Allocate(first),
                DriverCall::Allocate(second),
                DriverCall::Free(first),
            ]
        );

        Ok(())
    }

    /// Verifies a fault waits for an exact operation and is consumed once.
    #[test]
    fn faults_match_exactly_and_are_consumed_once() -> Result<(), VmiError> {
        let vm = test_vm();
        vm.insert_page(ORIGINAL_GFN, page_content(0x11));
        vm.insert_page(OTHER_GFN, page_content(0x22));
        vm.fail_on(DriverFault::Read(ORIGINAL_GFN));

        assert_eq!(vm.read_page(OTHER_GFN)?.as_ref(), page_content(0x22));
        assert!(matches!(
            vm.read_page(ORIGINAL_GFN),
            Err(VmiError::Other("injected read failure"))
        ));
        assert_eq!(vm.read_page(ORIGINAL_GFN)?.as_ref(), page_content(0x11));
        assert_eq!(
            vm.calls(),
            vec![
                DriverCall::Read(OTHER_GFN),
                DriverCall::Read(ORIGINAL_GFN),
                DriverCall::Read(ORIGINAL_GFN),
            ]
        );

        Ok(())
    }

    /// Verifies failed operations preserve state and use explicit call timing.
    #[test]
    fn failed_operations_preserve_state_and_call_timing() -> Result<(), VmiError> {
        let vm = test_vm();
        vm.insert_zeroed_page(ORIGINAL_GFN);

        vm.fail_on(DriverFault::Allocate);
        assert!(matches!(
            vm.allocate_gfn(),
            Err(VmiError::Other("injected allocation failure"))
        ));
        assert!(vm.calls().is_empty());
        assert!(!vm.has_page(FIRST_ALLOCATABLE_GFN));

        vm.fail_on(DriverFault::Write(ORIGINAL_GFN, 3));
        assert!(matches!(
            vm.write_page(ORIGINAL_GFN, 3, &[0xaa]),
            Err(VmiError::Other("injected write failure"))
        ));
        assert_eq!(vm.page(ORIGINAL_GFN), page_content(0));

        vm.fail_on(DriverFault::Change(VIEW, ORIGINAL_GFN, OTHER_GFN));
        assert!(matches!(
            vm.change_view_gfn(VIEW, ORIGINAL_GFN, OTHER_GFN),
            Err(VmiError::Other("injected view-change failure"))
        ));
        assert_eq!(vm.mapping(VIEW, ORIGINAL_GFN), None);

        vm.change_view_gfn(VIEW, ORIGINAL_GFN, OTHER_GFN)?;
        vm.clear_calls();
        vm.fail_on(DriverFault::Reset(VIEW, ORIGINAL_GFN));
        assert!(matches!(
            vm.reset_view_gfn(VIEW, ORIGINAL_GFN),
            Err(VmiError::Other("injected view-reset failure"))
        ));
        assert_eq!(vm.mapping(VIEW, ORIGINAL_GFN), Some(OTHER_GFN));
        assert_eq!(vm.calls(), vec![DriverCall::Reset(VIEW, ORIGINAL_GFN)]);

        Ok(())
    }

    /// Verifies metadata reports the AMD64 page geometry used by fixtures.
    #[test]
    fn metadata_matches_amd64_geometry() {
        let vm = test_vm();
        let info = vm.info();

        assert_eq!(info.page_size, Amd64::PAGE_SIZE);
        assert_eq!(info.page_shift, Amd64::PAGE_SHIFT);
        assert_eq!(info.max_gfn, Gfn(0xffff));
        assert_eq!(info.vcpus, 1);
    }

    /// Verifies unused call recording can avoid retaining driver operations.
    #[test]
    fn call_recording_can_be_disabled() -> Result<(), VmiError> {
        let vm = Amd64TestVm::without_call_recording(FIRST_ALLOCATABLE_GFN);
        vm.insert_zeroed_page(ORIGINAL_GFN);

        vm.read_page(ORIGINAL_GFN)?;
        vm.write_page(ORIGINAL_GFN, 0, &[1])?;
        vm.change_view_gfn(VIEW, ORIGINAL_GFN, OTHER_GFN)?;
        vm.reset_view_gfn(VIEW, ORIGINAL_GFN)?;
        let allocated = vm.allocate_gfn()?;
        vm.free_gfn(allocated)?;

        assert!(vm.calls().is_empty());

        Ok(())
    }

    /// Verifies duplicate page setup is rejected.
    #[test]
    #[should_panic(expected = "page already exists")]
    fn duplicate_pages_are_rejected() {
        let vm = test_vm();
        vm.insert_zeroed_page(ORIGINAL_GFN);
        vm.insert_zeroed_page(ORIGINAL_GFN);
    }

    /// Verifies incorrectly sized page setup is rejected.
    #[test]
    #[should_panic(expected = "invalid page size")]
    fn invalid_page_sizes_are_rejected() {
        let vm = test_vm();
        vm.insert_page(ORIGINAL_GFN, vec![0; Amd64::PAGE_SIZE as usize - 1]);
    }
}
