use super::{VmiOs, impl_predicate};
use crate::{Va, VmiDriver, VmiError, VmiVa};

impl_predicate! {
    /// Predicate used by [`VmiOsExt::find_module`].
    ///
    /// [`VmiOsExt::find_module`]: super::VmiOsExt::find_module
    pub trait ModulePredicate & impl for &str {
        fn matches(&self, module: &Os::Module<'_>) -> Result<bool, VmiError> {
            Ok(module.name()?.eq_ignore_ascii_case(self))
        }
    }

    #[any]
    pub struct AnyModule;
}

/// A trait for kernel modules.
///
/// This trait provides an abstraction over dynamically loaded modules,
/// such as kernel drivers and shared libraries, within a guest OS.
pub trait VmiOsModule<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver, Module<'a> = Self>;

    /// Returns the base address of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.DllBase`
    /// - **Linux**:
    ///   - since v6.4-rc1: `module::mem[0 /* MOD_TEXT */].base`
    ///   - before v6.4-rc1: `module::core_layout.base`
    fn base_address(&self) -> Result<Va, VmiError>;

    /// Returns the size of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.SizeOfImage`
    /// - **Linux**:
    ///   - since v6.4-rc1: sum of `module::mem[MOD_*].size`
    ///   - before v6.4-rc1: `module::init_layout.size + module::core_layout.size (+ module::data_layout.size)`
    fn size(&self) -> Result<u64, VmiError>;

    /// Returns the name of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.BaseDllName`
    /// - **Linux**: `module::name`
    fn name(&self) -> Result<String, VmiError>;
}
