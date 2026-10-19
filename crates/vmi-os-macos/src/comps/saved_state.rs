use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, MacOs, offset};

/// The user-mode register state of a macOS thread.
///
/// The kernel saves the user-mode registers of a thread here when the thread
/// enters the kernel, and the thread resumes from this state when it returns
/// to user mode.
///
/// # Implementation Details
///
/// Corresponds to `arm_saved_state`, whose 64-bit registers are in
/// `uss.ss_64`.
pub struct MacOsSavedState<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `arm_saved_state` structure.
    va: Va,
}

impl<Driver> VmiVa for MacOsSavedState<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsSavedState<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new macOS saved register state.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the instruction pointer.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `arm_saved_state.uss.ss_64.pc`.
    pub fn instruction_pointer(&self) -> Result<Va, VmiError> {
        let arm_saved_state = offset!(self.vmi, arm_saved_state);
        let arm_saved_state64 = offset!(self.vmi, arm_saved_state64);

        let pc = self
            .vmi
            .read_u64(self.va + arm_saved_state.uss.offset() + arm_saved_state64.pc.offset())?;

        Ok(Driver::Architecture::canonical_address(pc))
    }

    /// Returns the stack pointer.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `arm_saved_state.uss.ss_64.sp`.
    pub fn stack_pointer(&self) -> Result<Va, VmiError> {
        let arm_saved_state = offset!(self.vmi, arm_saved_state);
        let arm_saved_state64 = offset!(self.vmi, arm_saved_state64);

        let sp = self
            .vmi
            .read_u64(self.va + arm_saved_state.uss.offset() + arm_saved_state64.sp.offset())?;

        Ok(Driver::Architecture::canonical_address(sp))
    }
}
