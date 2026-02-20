use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{WindowsObject, macros::impl_offsets};
use crate::{ArchAdapter, WindowsOs};

/// A Windows trap frame.
///
/// A trap frame is a kernel structure that contains the context of a thread
/// when it is interrupted by an exception or an interrupt. It is used to save
/// the state of the thread so that it can be resumed later.
///
/// # Implementation Details
///
/// Corresponds to `_KTRAP_FRAME`.
pub struct WindowsTrapFrame<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_KTRAP_FRAME` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsTrapFrame<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsTrapFrame<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsTrapFrame<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsTrapFrame<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows trap frame.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the instruction pointer.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTRAP_FRAME.Rip`.
    pub fn instruction_pointer(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KTRAP_FRAME = &offsets._KTRAP_FRAME;

        self.vmi.read_va_native(self.va + KTRAP_FRAME.Rip.offset())
    }

    /// Returns the stack pointer.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTRAP_FRAME.Rsp`.
    pub fn stack_pointer(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KTRAP_FRAME = &offsets._KTRAP_FRAME;

        self.vmi.read_va_native(self.va + KTRAP_FRAME.Rsp.offset())
    }
}
