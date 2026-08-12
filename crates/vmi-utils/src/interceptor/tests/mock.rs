use std::fmt::Debug;

use vmi_arch_amd64::{Amd64, EventInterrupt, EventReason, EventSinglestep, Interrupt, Registers};
use vmi_core::{
    Architecture, Gfn, MemoryAccess, Pa, VcpuId, View, VmiCore, VmiDriver, VmiError, VmiEvent,
    VmiEventFlags, VmiInfo, VmiMappedPage, VmiRead, VmiViewControl, VmiVmControl, VmiWrite,
};

use crate::test_support::{Amd64TestVm, DriverCall, DriverFault};

/// Exposes the capabilities required by the interceptor.
pub(super) struct MockInterceptorDriver {
    /// Shared guest state and low-level driver behavior.
    vm: Amd64TestVm,
}

impl MockInterceptorDriver {
    /// Creates a driver with no pages or mappings.
    fn new() -> Self {
        Self {
            vm: Amd64TestVm::new(FIRST_SHADOW_GFN),
        }
    }

    /// Adds an initialized guest page.
    fn insert_page(&self, gfn: Gfn, content: Vec<u8>) {
        self.vm.insert_page(gfn, content);
    }

    /// Replaces an existing guest page.
    pub(super) fn replace_page(&self, gfn: Gfn, content: Vec<u8>) {
        self.vm.replace_page(gfn, content);
    }

    /// Returns a copy of a guest page.
    pub(super) fn page(&self, gfn: Gfn) -> Vec<u8> {
        self.vm.page(gfn)
    }

    /// Returns whether a guest page exists.
    pub(super) fn has_page(&self, gfn: Gfn) -> bool {
        self.vm.has_page(gfn)
    }

    /// Returns the explicit mapping for a view and original GFN.
    pub(super) fn mapping(&self, view: View, gfn: Gfn) -> Option<Gfn> {
        self.vm.mapping(view, gfn)
    }

    /// Configures one matching driver operation to fail.
    pub(super) fn fail_on(&self, fault: DriverFault) {
        self.vm.fail_on(fault);
    }

    /// Returns the chronological driver call history.
    pub(super) fn calls(&self) -> Vec<DriverCall> {
        self.vm.calls()
    }

    /// Clears the driver call history.
    pub(super) fn clear_calls(&self) {
        self.vm.clear_calls();
    }

    /// Counts allocations in the current call history.
    pub(super) fn allocation_count(&self) -> usize {
        self.vm
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Allocate(_)))
            .count()
    }

    /// Counts view resets in the current call history.
    pub(super) fn reset_count(&self) -> usize {
        self.vm
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Reset(..)))
            .count()
    }
}

impl VmiDriver for MockInterceptorDriver {
    type Architecture = Amd64;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.vm.info())
    }
}

impl VmiRead for MockInterceptorDriver {
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        self.vm.read_page(gfn)
    }
}

impl VmiWrite for MockInterceptorDriver {
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        self.vm.write_page(gfn, offset, content)
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
        self.vm.change_view_gfn(view, old_gfn, new_gfn)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        self.vm.reset_view_gfn(view, gfn)
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
        self.vm.allocate_gfn()
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        self.vm.free_gfn(gfn)
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
