use super::{VmiOs, impl_predicate};
use crate::{Va, VmiDriver, VmiError, VmiVa};

impl_predicate! {
    /// Predicate used for filtering user modules.
    pub trait UserModulePredicate & impl for &str {
        fn matches(&self, module: &Os::UserModule<'_>) -> Result<bool, VmiError> {
            Ok(module.name()?.eq_ignore_ascii_case(self))
        }
    }

    #[any]
    pub struct AnyUserModule;
}

/// A trait for user-mode modules.
///
/// This trait provides an abstraction over modules loaded into a process
/// address space, such as executables and shared libraries.
pub trait VmiOsUserModule<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver, UserModule<'a> = Self>;

    /// Returns the base address of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.DllBase`
    /// - **Linux**: `vm_area_struct.vm_start` of the region that maps file
    ///   offset 0
    fn base_address(&self) -> Result<Va, VmiError>;

    /// Returns the size of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.SizeOfImage`
    /// - **Linux**: The span of the `PT_LOAD` segments in the ELF program
    ///   headers
    fn size(&self) -> Result<u64, VmiError>;

    /// Returns the file name of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `LDR_DATA_TABLE_ENTRY.BaseDllName`
    /// - **Linux**: The name of the mapped file's dentry, or `DT_SONAME` for
    ///   the vDSO
    fn name(&self) -> Result<String, VmiError>;
}
