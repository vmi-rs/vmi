#[cfg(all(
    feature = "arch-amd64",
    feature = "os-windows",
    feature = "bpm",
    feature = "ptm"
))]
mod windows;

#[cfg(all(
    feature = "arch-amd64",
    feature = "os-linux",
    feature = "bpm",
    feature = "ptm"
))]
mod linux;

use vmi_core::{Architecture, Va, VmiCore, VmiError, VmiOs, VmiState};

use super::{ArchAdapter, CallBuilder};

/// Operating system-specific injection functionality.
pub trait OsAdapter: VmiOs {
    /// Prepares registers and stack for a function call according to OS conventions.
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Self::Driver>,
        registers: &mut <Self::Architecture as Architecture>::Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError>;

    /// Returns the base address of the image that `inject!` names, or
    /// `Ok(None)` when no image matches.
    ///
    /// The name comes before the `!` in `inject!(name!function(...))`. It is
    /// an identifier, such as `kernel32`, or a string literal that names a
    /// file, such as `"kernel32.dll"`.
    fn find_image(vmi: &VmiState<'_, Self>, name: &str) -> Result<Option<Va>, VmiError>;

    /// Returns the size of the red zone below the stack pointer.
    ///
    /// Code may keep data in the red zone without moving the stack pointer.
    /// Every step of a recipe starts below it. The default is 0.
    fn red_zone(&self, _registers: &<Self::Architecture as Architecture>::Registers) -> u64 {
        0
    }

    /// Copies bytes below the stack pointer and moves the stack pointer to
    /// them.
    ///
    /// Returns the address of the copy. The default writes as
    /// [`ArchAdapter::copy_bytes_to_stack`] does, whatever the guest's page
    /// tables permit.
    fn copy_to_stack(
        &self,
        vmi: &VmiCore<Self::Driver>,
        registers: &mut <Self::Architecture as Architecture>::Registers,
        data: &[u8],
        alignment: usize,
    ) -> Result<Va, VmiError>
    where
        Self::Architecture: ArchAdapter<Self::Driver>,
    {
        Self::Architecture::copy_bytes_to_stack(vmi, registers, data, alignment)
    }
}
