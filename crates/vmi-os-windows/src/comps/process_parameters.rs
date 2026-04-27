use vmi_core::{Pa, Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::WindowsWow64Kind;
use crate::{
    WindowsOs,
    arch::{ArchAdapter, StructLayout, StructLayout32, StructLayout64},
};

/// Field offsets for a `_RTL_USER_PROCESS_PARAMETERS` structure.
pub trait RtlUserProcessParameters<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `CurrentDirectory` field.
    const OFFSET_CURRENT_DIRECTORY: u64;

    /// Offset of the `DllPath` field.
    const OFFSET_DLL_PATH: u64;

    /// Offset of the `ImagePathName` field.
    const OFFSET_IMAGE_PATH_NAME: u64;

    /// Offset of the `CommandLine` field.
    const OFFSET_COMMAND_LINE: u64;
}

/// `_RTL_USER_PROCESS_PARAMETERS` structure layout.
pub struct RtlUserProcessParametersLayout;

impl RtlUserProcessParameters<StructLayout32> for RtlUserProcessParametersLayout {
    const OFFSET_CURRENT_DIRECTORY: u64 = 0x24;
    const OFFSET_DLL_PATH: u64 = 0x30;
    const OFFSET_IMAGE_PATH_NAME: u64 = 0x38;
    const OFFSET_COMMAND_LINE: u64 = 0x40;
}

impl RtlUserProcessParameters<StructLayout64> for RtlUserProcessParametersLayout {
    const OFFSET_CURRENT_DIRECTORY: u64 = 0x38;
    const OFFSET_DLL_PATH: u64 = 0x50;
    const OFFSET_IMAGE_PATH_NAME: u64 = 0x60;
    const OFFSET_COMMAND_LINE: u64 = 0x70;
}

/// Field offsets for a `_CURDIR` structure.
pub trait CurDir<Layout>
where
    Layout: StructLayout,
{
    /// Offset of the `DosPath` field.
    const OFFSET_DOS_PATH: u64;
}

/// `_CURDIR` structure layout.
pub struct CurDirLayout;

impl CurDir<StructLayout32> for CurDirLayout {
    const OFFSET_DOS_PATH: u64 = 0x00;
}

impl CurDir<StructLayout64> for CurDirLayout {
    const OFFSET_DOS_PATH: u64 = 0x00;
}

/// Process parameters accessor with a compile-time pointer width.
///
/// # Implementation Details
///
/// Corresponds to `_RTL_USER_PROCESS_PARAMETERS`.
pub struct WindowsProcessParametersBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    RtlUserProcessParametersLayout: RtlUserProcessParameters<Layout>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_RTL_USER_PROCESS_PARAMETERS` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    _marker: std::marker::PhantomData<Layout>,
}

impl<'a, Driver, Layout> WindowsProcessParametersBase<'a, Driver, Layout>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
    Layout: StructLayout,
    RtlUserProcessParametersLayout: RtlUserProcessParameters<Layout>,
    CurDirLayout: CurDir<Layout>,
{
    /// Creates a new process parameters accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self {
            vmi,
            va,
            root,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the current directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath`.
    pub fn current_directory(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va
                    + RtlUserProcessParametersLayout::OFFSET_CURRENT_DIRECTORY
                    + CurDirLayout::OFFSET_DOS_PATH,
                self.root,
            ),
        )
    }

    /// Returns the DLL search path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.DllPath`.
    pub fn dll_path(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va + RtlUserProcessParametersLayout::OFFSET_DLL_PATH,
                self.root,
            ),
        )
    }

    /// Returns the full path of the executable image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va + RtlUserProcessParametersLayout::OFFSET_IMAGE_PATH_NAME,
                self.root,
            ),
        )
    }

    /// Returns the command line used to launch the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    pub fn command_line(&self) -> Result<String, VmiError> {
        Layout::read_unicode_string(
            self.vmi,
            (
                self.va + RtlUserProcessParametersLayout::OFFSET_COMMAND_LINE,
                self.root,
            ),
        )
    }
}

enum WindowsProcessParametersWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    W32(WindowsProcessParametersBase<'a, Driver, StructLayout32>),
    W64(WindowsProcessParametersBase<'a, Driver, StructLayout64>),
}

impl<'a, Driver> WindowsProcessParametersWrapper<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn w32(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W32(WindowsProcessParametersBase::new(vmi, va, root))
    }

    fn w64(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self::W64(WindowsProcessParametersBase::new(vmi, va, root))
    }

    fn native(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        match vmi.registers().address_width() {
            4 => Self::w32(vmi, va, root),
            8 => Self::w64(vmi, va, root),
            _ => panic!("Unsupported address width"),
        }
    }

    fn current_directory(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.current_directory(),
            Self::W64(inner) => inner.current_directory(),
        }
    }

    fn dll_path(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.dll_path(),
            Self::W64(inner) => inner.dll_path(),
        }
    }

    fn image_path_name(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.image_path_name(),
            Self::W64(inner) => inner.image_path_name(),
        }
    }

    fn command_line(&self) -> Result<String, VmiError> {
        match self {
            Self::W32(inner) => inner.command_line(),
            Self::W64(inner) => inner.command_line(),
        }
    }
}

/// Process parameters accessor with a runtime pointer width.
///
/// Contains command-line arguments, environment variables, and other
/// startup information for a process.
///
/// # Implementation Details
///
/// Corresponds to `_RTL_USER_PROCESS_PARAMETERS`.
pub struct WindowsProcessParameters<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    inner: WindowsProcessParametersWrapper<'a, Driver>,
}

impl<'a, Driver> From<WindowsProcessParametersBase<'a, Driver, StructLayout32>>
    for WindowsProcessParameters<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsProcessParametersBase<'a, Driver, StructLayout32>) -> Self {
        Self {
            inner: WindowsProcessParametersWrapper::W32(value),
        }
    }
}

impl<'a, Driver> From<WindowsProcessParametersBase<'a, Driver, StructLayout64>>
    for WindowsProcessParameters<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsProcessParametersBase<'a, Driver, StructLayout64>) -> Self {
        Self {
            inner: WindowsProcessParametersWrapper::W64(value),
        }
    }
}

impl<Driver> VmiVa for WindowsProcessParameters<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            WindowsProcessParametersWrapper::W32(inner) => inner.va,
            WindowsProcessParametersWrapper::W64(inner) => inner.va,
        }
    }
}

impl<Driver> std::fmt::Debug for WindowsProcessParameters<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let current_directory = self.current_directory();
        let dll_path = self.dll_path();
        let image_path_name = self.image_path_name();
        let command_line = self.command_line();

        f.debug_struct("WindowsProcessParameters")
            .field("current_directory", &current_directory)
            .field("dll_path", &dll_path)
            .field("image_path_name", &image_path_name)
            .field("command_line", &command_line)
            .finish()
    }
}

impl<'a, Driver> WindowsProcessParameters<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new process parameters accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self::with_kind(vmi, va, vmi.translation_root(va), WindowsWow64Kind::Native)
    }

    /// Creates a new process parameters accessor with an explicit address
    /// space root and pointer width.
    pub fn with_kind(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => WindowsProcessParametersWrapper::native(vmi, va, root),
            WindowsWow64Kind::X86 => WindowsProcessParametersWrapper::w32(vmi, va, root),
        };

        Self { inner }
    }

    /// Returns the current directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath`.
    pub fn current_directory(&self) -> Result<String, VmiError> {
        self.inner.current_directory()
    }

    /// Returns the DLL search path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.DllPath`.
    pub fn dll_path(&self) -> Result<String, VmiError> {
        self.inner.dll_path()
    }

    /// Returns the full path of the executable image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        self.inner.image_path_name()
    }

    /// Returns the command line used to launch the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    pub fn command_line(&self) -> Result<String, VmiError> {
        self.inner.command_line()
    }
}
