use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::WindowsObject;
use crate::{ArchAdapter, WindowsOs, offset};

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
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_KTRAP_FRAME` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsTrapFrame<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsTrapFrame<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsTrapFrame<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsTrapFrame<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows trap frame.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the instruction pointer.
    ///
    /// # Implementation Details
    ///
    /// - **AMD64**: Corresponds to `_KTRAP_FRAME.Rip`.
    /// - **ARM64**: Corresponds to `_KTRAP_FRAME.Pc`.
    pub fn instruction_pointer(&self) -> Result<Va, VmiError> {
        let KTRAP_FRAME = offset!(self.vmi, _KTRAP_FRAME);

        #[cfg(target_arch = "x86_64")]
        let offset = KTRAP_FRAME.Rip.offset();
        #[cfg(target_arch = "aarch64")]
        let offset = KTRAP_FRAME.Pc.offset();

        self.vmi.read_va_native(self.va + offset)
    }

    /// Returns the stack pointer.
    ///
    /// # Implementation Details
    ///
    /// - **AMD64**: Corresponds to `_KTRAP_FRAME.Rsp`.
    /// - **ARM64**: Corresponds to `_KTRAP_FRAME.Sp`.
    pub fn stack_pointer(&self) -> Result<Va, VmiError> {
        let KTRAP_FRAME = offset!(self.vmi, _KTRAP_FRAME);

        #[cfg(target_arch = "x86_64")]
        let offset = KTRAP_FRAME.Rsp.offset();
        #[cfg(target_arch = "aarch64")]
        let offset = KTRAP_FRAME.Sp.offset();

        self.vmi.read_va_native(self.va + offset)
    }
}
