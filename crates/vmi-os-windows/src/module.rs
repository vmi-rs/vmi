use vmi_core::{os::VmiOsModule, Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows OS module.
pub struct WindowsOsModule<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> WindowsOsModule<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Create a new Windows module object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// The `EntryPoint` field of the module.
    ///
    /// The entry point of the module.
    pub fn entry_point(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .read_va_native(self.va + KLDR_DATA_TABLE_ENTRY.EntryPoint.offset)
    }

    /// The `FullDllName` field of the module.
    ///
    /// The full name of the module.
    pub fn full_name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .os()
            .read_unicode_string(self.va + KLDR_DATA_TABLE_ENTRY.FullDllName.offset)
    }
}

impl<'a, Driver> VmiOsModule for WindowsOsModule<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn base_address(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .read_va_native(self.va + KLDR_DATA_TABLE_ENTRY.DllBase.offset)
    }

    fn size(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        Ok(self
            .vmi
            .read_u32(self.va + KLDR_DATA_TABLE_ENTRY.SizeOfImage.offset)? as u64)
    }

    fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let KLDR_DATA_TABLE_ENTRY = &offsets._KLDR_DATA_TABLE_ENTRY;

        self.vmi
            .os()
            .read_unicode_string(self.va + KLDR_DATA_TABLE_ENTRY.BaseDllName.offset)
    }
}
