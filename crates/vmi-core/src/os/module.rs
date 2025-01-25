use crate::{Va, VmiError};

/// Represents information about a process in the target system.
pub trait VmiOsModule {
    /// The base address of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.DllBase`
    /// - **Linux**:
    ///   - since v6.4-rc1: `module::mem[0 /* MOD_TEXT */].base`
    ///   - before v6.4-rc1: `module::core_layout.base`
    fn base_address(&self) -> Result<Va, VmiError>;

    /// The size of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.SizeOfImage`
    /// - **Linux**:
    ///   - since v6.4-rc1: sum of `module::mem[MOD_*].size`
    ///   - before v6.4-rc1: `module::init_layout.size + module::core_layout.size (+ module::data_layout.size)`
    fn size(&self) -> Result<u64, VmiError>;

    /// The short name of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.BaseDllName`
    /// - **Linux**: `module::name`
    fn name(&self) -> Result<String, VmiError>;
}
