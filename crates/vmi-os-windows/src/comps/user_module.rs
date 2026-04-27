use vmi_core::{Pa, Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsUserModule};

use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _, offset};

/// A Windows user-mode module.
///
/// Represents a module loaded into a process address space, as enumerated
/// from the PEB loader data (`_LDR_DATA_TABLE_ENTRY`). Reads are performed
/// through a user-mode translation root, so the module's PE image and
/// metadata are accessible even on KPTI-enabled systems.
///
/// # Implementation Details
///
/// Corresponds to `_LDR_DATA_TABLE_ENTRY`.
pub struct WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_LDR_DATA_TABLE_ENTRY` structure.
    va: Va,

    /// The user-mode translation root.
    root: Pa,
}

impl<Driver> VmiVa for WindowsUserModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows user-mode module.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Returns the entry point of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.EntryPoint`.
    pub fn entry_point(&self) -> Result<Va, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        self.vmi.read_va_native_in((
            self.va + LDR_DATA_TABLE_ENTRY.EntryPoint.offset(),
            self.root,
        ))
    }

    /// Returns the full name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.FullDllName`.
    pub fn full_name(&self) -> Result<String, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        self.vmi.os().read_unicode_string_in((
            self.va + LDR_DATA_TABLE_ENTRY.FullDllName.offset(),
            self.root,
        ))
    }

    /// Returns the timestamp of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.TimeDateStamp`.
    pub fn time_date_stamp(&self) -> Result<u32, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        self.vmi.read_u32_in((
            self.va + LDR_DATA_TABLE_ENTRY.TimeDateStamp.offset(),
            self.root,
        ))
    }
}

impl<'a, Driver> VmiOsUserModule<'a, Driver> for WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.DllBase`.
    fn base_address(&self) -> Result<Va, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        self.vmi
            .read_va_native_in((self.va + LDR_DATA_TABLE_ENTRY.DllBase.offset(), self.root))
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.SizeOfImage`.
    fn size(&self) -> Result<u64, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        Ok(self.vmi.read_u32_in((
            self.va + LDR_DATA_TABLE_ENTRY.SizeOfImage.offset(),
            self.root,
        ))? as u64)
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.BaseDllName`.
    fn name(&self) -> Result<String, VmiError> {
        let LDR_DATA_TABLE_ENTRY = offset!(self.vmi, _LDR_DATA_TABLE_ENTRY);

        self.vmi.os().read_unicode_string_in((
            self.va + LDR_DATA_TABLE_ENTRY.BaseDllName.offset(),
            self.root,
        ))
    }
}
