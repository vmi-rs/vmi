use super::VmiOs;
use crate::{Va, VmiDriver, VmiError, VmiVa};

/// A trait for user-mode modules.
///
/// This trait provides an abstraction over modules loaded into a process
/// address space, such as executables and shared libraries.
pub trait VmiOsUserModule<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver>;

    /// Returns the base address of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.DllBase`
    fn base_address(&self) -> Result<Va, VmiError>;

    /// Returns the size of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.SizeOfImage`
    fn size(&self) -> Result<u64, VmiError>;

    /// Returns the name of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.BaseDllName`
    fn name(&self) -> Result<String, VmiError>;
}
