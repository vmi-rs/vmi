use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    fmt::Debug,
};

use vmi_arch_amd64::{Amd64, EventInterrupt, EventReason, EventSinglestep, Interrupt, Registers};
use vmi_core::{
    Architecture, Gfn, MemoryAccess, Pa, VcpuId, View, VmiCore, VmiDriver, VmiError, VmiEvent,
    VmiEventFlags, VmiInfo, VmiMappedPage, VmiRead, VmiViewControl, VmiVmControl, VmiWrite,
};

/// One driver operation that should fail when next attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// Fails shadow-page allocation.
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

/// One observable driver call made by the interceptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
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

/// Models guest pages, view mappings, allocation, and injected failures.
pub(super) struct MockInterceptorDriver {
    /// Guest physical pages keyed by GFN.
    pages: RefCell<HashMap<Gfn, Vec<u8>>>,

    /// Explicit shadow mappings keyed by view and original GFN.
    mappings: RefCell<HashMap<(View, Gfn), Gfn>>,

    /// GFN returned by the next successful allocation.
    next_gfn: Cell<u64>,

    /// Driver operation that should fail once.
    fault: Cell<Option<Fault>>,

    /// Calls attempted against the driver in chronological order.
    calls: RefCell<Vec<Call>>,
}

impl MockInterceptorDriver {
    /// Creates a driver with no pages or mappings.
    fn new() -> Self {
        Self {
            pages: RefCell::new(HashMap::new()),
            mappings: RefCell::new(HashMap::new()),
            next_gfn: Cell::new(FIRST_SHADOW_GFN.0),
            fault: Cell::new(None),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Adds an initialized guest page.
    fn insert_page(&self, gfn: Gfn, content: Vec<u8>) {
        assert_eq!(content.len(), Amd64::PAGE_SIZE as usize);
        assert!(self.pages.borrow_mut().insert(gfn, content).is_none());
    }

    /// Replaces an existing guest page.
    pub(super) fn replace_page(&self, gfn: Gfn, content: Vec<u8>) {
        assert_eq!(content.len(), Amd64::PAGE_SIZE as usize);
        let previous = self.pages.borrow_mut().insert(gfn, content);
        assert!(previous.is_some(), "no page at {gfn:?}");
    }

    /// Returns a copy of a guest page.
    pub(super) fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.pages
            .borrow()
            .get(&gfn)
            .unwrap_or_else(|| panic!("no page at {gfn:?}"))
            .clone()
    }

    /// Returns whether a guest page exists.
    pub(super) fn has_page(&self, gfn: Gfn) -> bool {
        self.pages.borrow().contains_key(&gfn)
    }

    /// Returns the explicit mapping for a view and original GFN.
    pub(super) fn mapping(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.mappings.borrow().get(&(view, gfn)).copied()
    }

    /// Configures one matching driver operation to fail.
    pub(super) fn fail_on(&self, fault: Fault) {
        assert!(self.fault.replace(Some(fault)).is_none());
    }

    /// Consumes and reports a matching configured failure.
    fn take_fault(&self, actual: Fault) -> bool {
        if self.fault.get() == Some(actual) {
            self.fault.set(None);
            true
        }
        else {
            false
        }
    }

    /// Returns the chronological driver call history.
    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    /// Clears the driver call history.
    pub(super) fn clear_calls(&self) {
        self.calls.borrow_mut().clear();
    }

    /// Counts allocations in the current call history.
    pub(super) fn allocation_count(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Allocate(_)))
            .count()
    }

    /// Counts view resets in the current call history.
    pub(super) fn reset_count(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Reset(..)))
            .count()
    }
}

impl VmiDriver for MockInterceptorDriver {
    type Architecture = Amd64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(VmiInfo {
            page_size: Amd64::PAGE_SIZE,
            page_shift: Amd64::PAGE_SHIFT,
            max_gfn: Gfn(0xffff),
            vcpus: 1,
        })
    }
}

impl VmiRead for MockInterceptorDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.calls.borrow_mut().push(Call::Read(gfn));
        if self.take_fault(Fault::Read(gfn)) {
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
}

impl VmiWrite for MockInterceptorDriver {
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        self.calls
            .borrow_mut()
            .push(Call::Write(gfn, offset, content.len()));
        if self.take_fault(Fault::Write(gfn, offset)) {
            return Err(VmiError::Other("injected write failure"));
        }

        let page = {
            let mut pages = self.pages.borrow_mut();
            let page = pages
                .get_mut(&gfn)
                .ok_or(VmiError::Other("page not found"))?;
            let offset = offset as usize;
            let end = offset
                .checked_add(content.len())
                .ok_or(VmiError::OutOfBounds)?;
            let destination = page.get_mut(offset..end).ok_or(VmiError::OutOfBounds)?;
            destination.copy_from_slice(content);
            page.clone()
        };

        Ok(VmiMappedPage::new(page))
    }
}

impl VmiViewControl for MockInterceptorDriver {
    fn default_view(&self) -> View {
        View(0)
    }

    fn create_view(&self, _default_access: MemoryAccess) -> Result<View, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn destroy_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn switch_to_view(&self, _view: View) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        self.calls
            .borrow_mut()
            .push(Call::Change(view, old_gfn, new_gfn));
        if self.take_fault(Fault::Change(view, old_gfn, new_gfn)) {
            return Err(VmiError::Other("injected view-change failure"));
        }

        self.mappings.borrow_mut().insert((view, old_gfn), new_gfn);
        Ok(())
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.calls.borrow_mut().push(Call::Reset(view, gfn));
        if self.take_fault(Fault::Reset(view, gfn)) {
            return Err(VmiError::Other("injected view-reset failure"));
        }

        self.mappings.borrow_mut().remove(&(view, gfn));
        Ok(())
    }
}

impl VmiVmControl for MockInterceptorDriver {
    fn pause(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn resume(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        if self.take_fault(Fault::Allocate) {
            return Err(VmiError::Other("injected allocation failure"));
        }

        let gfn = Gfn(self.next_gfn.get());
        self.next_gfn.set(gfn.0 + 1);
        self.pages
            .borrow_mut()
            .insert(gfn, vec![0; Amd64::PAGE_SIZE as usize]);
        self.calls.borrow_mut().push(Call::Allocate(gfn));
        Ok(gfn)
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.calls.borrow_mut().push(Call::Free(gfn));
        self.pages
            .borrow_mut()
            .remove(&gfn)
            .ok_or(VmiError::Other("page not found"))?;
        Ok(())
    }

    fn inject_interrupt(&self, _vcpu: VcpuId, _interrupt: Interrupt) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }
}

/// Original GFN used by tests.
pub(super) const ORIGINAL_GFN: Gfn = Gfn(0x10);

/// Second original GFN used by isolation tests.
pub(super) const OTHER_GFN: Gfn = Gfn(0x20);

/// First GFN returned for a shadow-page allocation.
pub(super) const FIRST_SHADOW_GFN: Gfn = Gfn(0x1000);

/// Primary view used by tests.
pub(super) const VIEW: View = View(7);

/// Secondary view used by isolation tests.
pub(super) const OTHER_VIEW: View = View(8);

/// Primary breakpoint offset used by tests.
pub(super) const OFFSET: u64 = 0x123;

/// Secondary breakpoint offset used by tests.
pub(super) const OTHER_OFFSET: u64 = 0xabc;

/// Builds deterministic page content from a seed byte.
pub(super) fn page_content(seed: u8) -> Vec<u8> {
    (0..Amd64::PAGE_SIZE)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

/// Creates a VMI core with two initialized original pages.
pub(super) fn test_vmi() -> Result<VmiCore<MockInterceptorDriver>, VmiError> {
    let driver = MockInterceptorDriver::new();
    driver.insert_page(ORIGINAL_GFN, page_content(0x10));
    driver.insert_page(OTHER_GFN, page_content(0x80));
    VmiCore::new(driver)
}

/// Combines a GFN and in-page byte offset into a physical address.
pub(super) fn address(gfn: Gfn, offset: u64) -> Pa {
    Amd64::pa_from_gfn(gfn) + offset
}

/// Returns page content with a breakpoint inserted at the given offset.
pub(super) fn with_breakpoint(mut page: Vec<u8>, offset: u64) -> Vec<u8> {
    let offset = offset as usize;
    page[offset..offset + Amd64::BREAKPOINT.len()].copy_from_slice(Amd64::BREAKPOINT);
    page
}

/// Creates a software-breakpoint event at the given page offset.
pub(super) fn breakpoint_event(gfn: Gfn, view: Option<View>, offset: u64) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: 0xffff_8000_0000_0000 | offset,
        ..Default::default()
    };

    VmiEvent::new(
        VcpuId(0),
        VmiEventFlags::default(),
        view,
        registers,
        EventReason::Interrupt(EventInterrupt {
            gfn,
            interrupt: Interrupt::breakpoint(Amd64::BREAKPOINT.len() as u8),
        }),
    )
}

/// Creates a non-breakpoint event at the given page offset.
pub(super) fn non_breakpoint_event(gfn: Gfn, view: Option<View>, offset: u64) -> VmiEvent<Amd64> {
    let registers = Registers {
        rip: offset,
        ..Default::default()
    };

    VmiEvent::new(
        VcpuId(0),
        VmiEventFlags::default(),
        view,
        registers,
        EventReason::Singlestep(EventSinglestep { gfn }),
    )
}

/// Asserts that a result contains an injected driver error.
pub(super) fn assert_injected_error<T: Debug>(result: Result<T, VmiError>) {
    assert!(
        matches!(result, Err(VmiError::Other(message)) if message.starts_with("injected")),
        "expected an injected driver error, got {result:?}"
    );
}
