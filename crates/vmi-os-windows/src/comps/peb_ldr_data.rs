use vmi_core::{Pa, Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{WindowsUserModule, WindowsUserModuleBase, WindowsWow64Kind};
use crate::{
    ArchAdapter, ListEntry, ListEntryIterator, ListEntryIteratorBase, WindowsOs,
    arch::{StructLayout, StructLayout32, StructLayout64},
    iter::ListEntryLayout,
};

/// Field offsets for a `_PEB_LDR_DATA` structure.
pub trait PebLdrData<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `InLoadOrderModuleList` field.
    const OFFSET_IN_LOAD_ORDER_MODULE_LIST: u64;

    /// Offset of the `InMemoryOrderModuleList` field.
    const OFFSET_IN_MEMORY_ORDER_MODULE_LIST: u64;

    /// Offset of the `InInitializationOrderModuleList` field.
    const OFFSET_IN_INITIALIZATION_ORDER_MODULE_LIST: u64;
}

/// `_PEB_LDR_DATA` structure layout.
pub struct PebLdrDataLayout;

impl PebLdrData<StructLayout32> for PebLdrDataLayout {
    const OFFSET_IN_LOAD_ORDER_MODULE_LIST: u64 = 0x0c;
    const OFFSET_IN_MEMORY_ORDER_MODULE_LIST: u64 = 0x14;
    const OFFSET_IN_INITIALIZATION_ORDER_MODULE_LIST: u64 = 0x1c;
}

impl PebLdrData<StructLayout64> for PebLdrDataLayout {
    const OFFSET_IN_LOAD_ORDER_MODULE_LIST: u64 = 0x10;
    const OFFSET_IN_MEMORY_ORDER_MODULE_LIST: u64 = 0x20;
    const OFFSET_IN_INITIALIZATION_ORDER_MODULE_LIST: u64 = 0x30;
}

/// Field offsets for a `_LDR_DATA_TABLE_ENTRY` structure.
pub trait LdrDataTableEntry<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `InLoadOrderLinks` field.
    const OFFSET_IN_LOAD_ORDER_LINKS: u64;

    /// Offset of the `InMemoryOrderLinks` field.
    const OFFSET_IN_MEMORY_ORDER_LINKS: u64;

    /// Offset of the `InInitializationOrderLinks` field.
    const OFFSET_IN_INITIALIZATION_ORDER_LINKS: u64;

    /// Offset of the `DllBase` field.
    const OFFSET_DLL_BASE: u64;

    /// Offset of the `EntryPoint` field.
    const OFFSET_ENTRY_POINT: u64;

    /// Offset of the `SizeOfImage` field.
    const OFFSET_SIZE_OF_IMAGE: u64;

    /// Offset of the `FullDllName` field.
    const OFFSET_FULL_DLL_NAME: u64;

    /// Offset of the `BaseDllName` field.
    const OFFSET_BASE_DLL_NAME: u64;

    /// Offset of the `TimeDateStamp` field.
    const OFFSET_TIME_DATE_STAMP: u64;
}

/// `_LDR_DATA_TABLE_ENTRY` structure layout.
pub struct LdrDataTableEntryLayout;

impl LdrDataTableEntry<StructLayout32> for LdrDataTableEntryLayout {
    const OFFSET_IN_LOAD_ORDER_LINKS: u64 = 0x00;
    const OFFSET_IN_MEMORY_ORDER_LINKS: u64 = 0x08;
    const OFFSET_IN_INITIALIZATION_ORDER_LINKS: u64 = 0x10;
    const OFFSET_DLL_BASE: u64 = 0x18;
    const OFFSET_ENTRY_POINT: u64 = 0x1c;
    const OFFSET_SIZE_OF_IMAGE: u64 = 0x20;
    const OFFSET_FULL_DLL_NAME: u64 = 0x24;
    const OFFSET_BASE_DLL_NAME: u64 = 0x2c;
    const OFFSET_TIME_DATE_STAMP: u64 = 0x44;
}

impl LdrDataTableEntry<StructLayout64> for LdrDataTableEntryLayout {
    const OFFSET_IN_LOAD_ORDER_LINKS: u64 = 0x00;
    const OFFSET_IN_MEMORY_ORDER_LINKS: u64 = 0x10;
    const OFFSET_IN_INITIALIZATION_ORDER_LINKS: u64 = 0x20;
    const OFFSET_DLL_BASE: u64 = 0x30;
    const OFFSET_ENTRY_POINT: u64 = 0x38;
    const OFFSET_SIZE_OF_IMAGE: u64 = 0x40;
    const OFFSET_FULL_DLL_NAME: u64 = 0x48;
    const OFFSET_BASE_DLL_NAME: u64 = 0x58;
    const OFFSET_TIME_DATE_STAMP: u64 = 0x80;
}

/// PEB loader data accessor with a compile-time pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_PEB_LDR_DATA`.
pub struct WindowsPebLdrDataBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    PebLdrDataLayout: PebLdrData<Layout>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_PEB_LDR_DATA` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> WindowsPebLdrDataBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    ListEntryLayout: ListEntry<Layout>,
    PebLdrDataLayout: PebLdrData<Layout>,
    LdrDataTableEntryLayout: LdrDataTableEntry<Layout>,
{
    /// Creates a new PEB loader data accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns an iterator over modules in load order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InLoadOrderModuleList`.
    pub fn in_load_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModuleBase<'a, Driver, Layout>, VmiError>>
        + use<'a, Driver, Layout>,
        VmiError,
    > {
        let vmi = self.vmi;
        let root = self.root;
        Ok(self
            .in_load_order_modules_inner()
            .map(move |result| result.map(|va| WindowsUserModuleBase::new(vmi, va, root))))
    }

    /// Returns an iterator over modules in memory order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InMemoryOrderModuleList`.
    pub fn in_memory_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModuleBase<'a, Driver, Layout>, VmiError>>
        + use<'a, Driver, Layout>,
        VmiError,
    > {
        let vmi = self.vmi;
        let root = self.root;
        Ok(self
            .in_memory_order_modules_inner()
            .map(move |result| result.map(|va| WindowsUserModuleBase::new(vmi, va, root))))
    }

    /// Returns an iterator over modules in initialization order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InInitializationOrderModuleList`.
    pub fn in_initialization_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModuleBase<'a, Driver, Layout>, VmiError>>
        + use<'a, Driver, Layout>,
        VmiError,
    > {
        let vmi = self.vmi;
        let root = self.root;
        Ok(self
            .in_initialization_order_modules_inner()
            .map(move |result| result.map(|va| WindowsUserModuleBase::new(vmi, va, root))))
    }

    fn in_load_order_modules_inner(&self) -> ListEntryIteratorBase<'a, Driver, Layout> {
        self.make_iterator(
            self.va + PebLdrDataLayout::OFFSET_IN_LOAD_ORDER_MODULE_LIST,
            LdrDataTableEntryLayout::OFFSET_IN_LOAD_ORDER_LINKS,
        )
    }

    fn in_memory_order_modules_inner(&self) -> ListEntryIteratorBase<'a, Driver, Layout> {
        self.make_iterator(
            self.va + PebLdrDataLayout::OFFSET_IN_MEMORY_ORDER_MODULE_LIST,
            LdrDataTableEntryLayout::OFFSET_IN_MEMORY_ORDER_LINKS,
        )
    }

    fn in_initialization_order_modules_inner(&self) -> ListEntryIteratorBase<'a, Driver, Layout> {
        self.make_iterator(
            self.va + PebLdrDataLayout::OFFSET_IN_INITIALIZATION_ORDER_MODULE_LIST,
            LdrDataTableEntryLayout::OFFSET_IN_INITIALIZATION_ORDER_LINKS,
        )
    }

    fn make_iterator(
        &self,
        list_head: Va,
        link_offset: u64,
    ) -> ListEntryIteratorBase<'a, Driver, Layout> {
        ListEntryIteratorBase::new(self.vmi, list_head, link_offset, self.root)
    }
}

enum WindowsPebLdrDataWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(WindowsPebLdrDataBase<'a, Driver, StructLayout32>),
    W64(WindowsPebLdrDataBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> WindowsPebLdrDataWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W32(WindowsPebLdrDataBase::new(vmi, va, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W64(WindowsPebLdrDataBase::new(vmi, va, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, va, root),
            8 => Self::w64(vmi, va, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn in_load_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let (iter, vmi, root, kind) = match self {
            Self::W32(inner) => (
                ListEntryIterator::from(inner.in_load_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::X86,
            ),
            Self::W64(inner) => (
                ListEntryIterator::from(inner.in_load_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::Native,
            ),
        };

        Ok(iter
            .map(move |result| result.map(|va| WindowsUserModule::with_kind(vmi, va, root, kind))))
    }

    fn in_memory_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let (iter, vmi, root, kind) = match self {
            Self::W32(inner) => (
                ListEntryIterator::from(inner.in_memory_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::X86,
            ),
            Self::W64(inner) => (
                ListEntryIterator::from(inner.in_memory_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::Native,
            ),
        };

        Ok(iter
            .map(move |result| result.map(|va| WindowsUserModule::with_kind(vmi, va, root, kind))))
    }

    fn in_initialization_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let (iter, vmi, root, kind) = match self {
            Self::W32(inner) => (
                ListEntryIterator::from(inner.in_initialization_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::X86,
            ),
            Self::W64(inner) => (
                ListEntryIterator::from(inner.in_initialization_order_modules_inner()),
                inner.vmi,
                inner.root,
                WindowsWow64Kind::Native,
            ),
        };

        Ok(iter
            .map(move |result| result.map(|va| WindowsUserModule::with_kind(vmi, va, root, kind))))
    }
}

/// PEB loader data accessor with a runtime pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_PEB_LDR_DATA`.
pub struct WindowsPebLdrData<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: WindowsPebLdrDataWrapper<'a, Driver>,
}

impl<'a, Driver> From<WindowsPebLdrDataBase<'a, Driver, StructLayout32>>
    for WindowsPebLdrData<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsPebLdrDataBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: WindowsPebLdrDataWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<WindowsPebLdrDataBase<'a, Driver, StructLayout64>>
    for WindowsPebLdrData<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsPebLdrDataBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: WindowsPebLdrDataWrapper::W64(value),
        }
    }
}

impl<Driver> VmiVa for WindowsPebLdrData<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            WindowsPebLdrDataWrapper::W32(inner) => inner.va,
            WindowsPebLdrDataWrapper::W64(inner) => inner.va,
        }
    }
}

impl<'a, Driver> WindowsPebLdrData<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new PEB loader data accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self::with_kind(vmi, va, vmi.translation_root(va), WindowsWow64Kind::Native)
    }

    /// Creates a new PEB loader data accessor with an explicit address space
    /// root and pointer width.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => WindowsPebLdrDataWrapper::native(vmi, va, root),
            WindowsWow64Kind::X86 => WindowsPebLdrDataWrapper::w32(vmi, va, root),
        };

        Self { inner }
    }

    /// Returns an iterator over modules in load order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InLoadOrderModuleList`.
    pub fn in_load_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        self.inner.in_load_order_modules()
    }

    /// Returns an iterator over modules in memory order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InMemoryOrderModuleList`.
    pub fn in_memory_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        self.inner.in_memory_order_modules()
    }

    /// Returns an iterator over modules in initialization order.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB_LDR_DATA.InInitializationOrderModuleList`.
    pub fn in_initialization_order_modules(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsUserModule<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        self.inner.in_initialization_order_modules()
    }
}
