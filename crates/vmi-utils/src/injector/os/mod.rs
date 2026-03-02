#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
mod windows;

use vmi_core::{Architecture, VmiCore, VmiError, VmiOs};

use super::CallBuilder;

/// Operating system-specific injection functionality.
pub trait OsAdapter: VmiOs {
    /// Prepares registers and stack for a function call according to OS conventions.
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Self::Driver>,
        registers: &mut <Self::Architecture as Architecture>::Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError>;
}
