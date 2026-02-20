#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
pub mod windows;

use vmi_core::{Architecture, VmiCore, VmiDriver, VmiError, VmiOs};

use super::CallBuilder;

/// Operating system-specific injection functionality.
pub trait OsAdapter<Driver>: VmiOs<Driver>
where
    Driver: VmiDriver,
{
    /// Prepares registers and stack for a function call according to OS conventions.
    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &mut <Driver::Architecture as Architecture>::Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError>;
}
