use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsModule};

use super::macros::impl_offsets;
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

/// A Windows kernel module.
///
/// A module in Windows refers to a loaded executable or driver,
/// typically tracked in the kernel's module list.
///
/// # Implementation Details
///
/// Corresponds to `_KLDR_DATA_TABLE_ENTRY`.
pub struct WindowsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_KLDR_DATA_TABLE_ENTRY` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows kernel module.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the entry point of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KLDR_DATA_TABLE_ENTRY.EntryPoint`.
    pub fn entry_point(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .read_va_native(self.va + KLDR_DATA_TABLE_ENTRY.EntryPoint.offset())
    }

    /// Returns the full name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KLDR_DATA_TABLE_ENTRY.FullDllName`.
    pub fn full_name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .os()
            .read_unicode_string(self.va + KLDR_DATA_TABLE_ENTRY.FullDllName.offset())
    }
}

impl<'a, Driver> VmiOsModule<'a, Driver> for WindowsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KLDR_DATA_TABLE_ENTRY.DllBase`.
    fn base_address(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .read_va_native(self.va + KLDR_DATA_TABLE_ENTRY.DllBase.offset())
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KLDR_DATA_TABLE_ENTRY.SizeOfImage`.
    fn size(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        Ok(self
            .vmi
            .read_u32(self.va + KLDR_DATA_TABLE_ENTRY.SizeOfImage.offset())? as u64)
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KLDR_DATA_TABLE_ENTRY.BaseDllName`.
    fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .os()
            .read_unicode_string(self.va + KLDR_DATA_TABLE_ENTRY.BaseDllName.offset())
    }
}
