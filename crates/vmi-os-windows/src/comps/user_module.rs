use vmi_core::{
    Pa, Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsUserModule,
};

use super::{LdrDataTableEntry, LdrDataTableEntryLayout, WindowsWow64Kind};
use crate::{
    WindowsOs,
    arch::{ArchAdapter, StructLayout, StructLayout32, StructLayout64},
};

/// User-mode module accessor with a compile-time pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_LDR_DATA_TABLE_ENTRY`.
pub struct WindowsUserModuleBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    LdrDataTableEntryLayout: LdrDataTableEntry<Layout>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_LDR_DATA_TABLE_ENTRY` structure.
    va: Va,

    /// The user-mode translation root.
    root: Pa,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> WindowsUserModuleBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    LdrDataTableEntryLayout: LdrDataTableEntry<Layout>,
{
    /// Creates a new user-mode module accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the entry point of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.EntryPoint`.
    pub fn entry_point(&self) -> Result<Va, VmiError> {
        Layout::read_va(
            self.vmi,
            (
                self.va + LdrDataTableEntryLayout::OFFSET_ENTRY_POINT,
                self.root,
            ),
        )
    }

    /// Returns the full name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.FullDllName`.
    pub fn full_name(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va + LdrDataTableEntryLayout::OFFSET_FULL_DLL_NAME,
                self.root,
            ),
        )
    }

    /// Returns the timestamp of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.TimeDateStamp`.
    pub fn time_date_stamp(&self) -> Result<u32, VmiError> {
        self.vmi.read_u32_in((
            self.va + LdrDataTableEntryLayout::OFFSET_TIME_DATE_STAMP,
            self.root,
        ))
    }

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.DllBase`.
    pub fn base_address(&self) -> Result<Va, VmiError> {
        Layout::read_va(
            self.vmi,
            (
                self.va + LdrDataTableEntryLayout::OFFSET_DLL_BASE,
                self.root,
            ),
        )
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.SizeOfImage`.
    pub fn size(&self) -> Result<u64, VmiError> {
        Ok(self.vmi.read_u32_in((
            self.va + LdrDataTableEntryLayout::OFFSET_SIZE_OF_IMAGE,
            self.root,
        ))? as u64)
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.BaseDllName`.
    pub fn name(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va + LdrDataTableEntryLayout::OFFSET_BASE_DLL_NAME,
                self.root,
            ),
        )
    }
}

enum WindowsUserModuleWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(WindowsUserModuleBase<'a, Driver, StructLayout32>),
    W64(WindowsUserModuleBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> WindowsUserModuleWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W32(WindowsUserModuleBase::new(vmi, va, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W64(WindowsUserModuleBase::new(vmi, va, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, va, root),
            8 => Self::w64(vmi, va, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn entry_point(&self) -> Result<Va, VmiError> {
        match self {
            Self::W32(inner) => inner.entry_point(),
            Self::W64(inner) => inner.entry_point(),
        }
    }

    fn full_name(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.full_name(),
            Self::W64(inner) => inner.full_name(),
        }
    }

    fn time_date_stamp(&self) -> Result<u32, VmiError> {
        match self {
            Self::W32(inner) => inner.time_date_stamp(),
            Self::W64(inner) => inner.time_date_stamp(),
        }
    }

    fn base_address(&self) -> Result<Va, VmiError> {
        match self {
            Self::W32(inner) => inner.base_address(),
            Self::W64(inner) => inner.base_address(),
        }
    }

    fn size(&self) -> Result<u64, VmiError> {
        match self {
            Self::W32(inner) => inner.size(),
            Self::W64(inner) => inner.size(),
        }
    }

    fn name(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.name(),
            Self::W64(inner) => inner.name(),
        }
    }
}

/// A Windows user-mode module.
///
/// Represents a module loaded into a process address space, as enumerated
/// from the PEB loader data (`_LDR_DATA_TABLE_ENTRY`). Reads are performed
/// through a user-mode translation root, so the module's PE image and
/// metadata are accessible even on KPTI-enabled systems.
///
/// A module enumerated from the 32-bit loader list of a WoW64 process uses the
/// 32-bit structure layout. The pointer width is selected at construction, so
/// the same type serves both native and WoW64 modules.
///
/// # Implementation Details
///
/// Corresponds to `_LDR_DATA_TABLE_ENTRY`.
pub struct WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: WindowsUserModuleWrapper<'a, Driver>,
}

impl<'a, Driver> From<WindowsUserModuleBase<'a, Driver, StructLayout32>>
    for WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsUserModuleBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: WindowsUserModuleWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<WindowsUserModuleBase<'a, Driver, StructLayout64>>
    for WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsUserModuleBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: WindowsUserModuleWrapper::W64(value),
        }
    }
}

impl<Driver> VmiVa for WindowsUserModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            WindowsUserModuleWrapper::W32(inner) => inner.va,
            WindowsUserModuleWrapper::W64(inner) => inner.va,
        }
    }
}

impl<'a, Driver> WindowsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new native Windows user-mode module.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::with_kind(vmi, va, root, WindowsWow64Kind::Native)
    }

    /// Creates a new Windows user-mode module with an explicit address space
    /// layout, selecting the native or 32-bit (WoW64) `_LDR_DATA_TABLE_ENTRY`.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => WindowsUserModuleWrapper::native(vmi, va, root),
            WindowsWow64Kind::X86 => WindowsUserModuleWrapper::w32(vmi, va, root),
        };

        Self { inner }
    }

    /// Returns the entry point of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.EntryPoint`.
    pub fn entry_point(&self) -> Result<Va, VmiError> {
        self.inner.entry_point()
    }

    /// Returns the full name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.FullDllName`.
    pub fn full_name(&self) -> Result<String, VmiError> {
        self.inner.full_name()
    }

    /// Returns the timestamp of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.TimeDateStamp`.
    pub fn time_date_stamp(&self) -> Result<u32, VmiError> {
        self.inner.time_date_stamp()
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
        self.inner.base_address()
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.SizeOfImage`.
    fn size(&self) -> Result<u64, VmiError> {
        self.inner.size()
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_LDR_DATA_TABLE_ENTRY.BaseDllName`.
    fn name(&self) -> Result<String, VmiError> {
        self.inner.name()
    }
}
