use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState};

use super::WindowsWow64Kind;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows process parameters object.
pub struct WindowsProcessParameters<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: Inner<'a, Driver>,
}

impl<Driver> From<WindowsProcessParameters<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsProcessParameters<Driver>) -> Self {
        match &value.inner {
            Inner::Native(inner) => inner.va,
            Inner::X86(inner) => inner.va,
        }
    }
}

impl<Driver> std::fmt::Debug for WindowsProcessParameters<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let current_directory = self.current_directory();
        let dll_path = self.dll_path();
        let image_path_name = self.image_path_name();
        let command_line = self.command_line();

        f.debug_struct("WindowsOsProcessParameters")
            .field("current_directory", &current_directory)
            .field("dll_path", &dll_path)
            .field("image_path_name", &image_path_name)
            .field("command_line", &command_line)
            .finish()
    }
}

impl<'a, Driver> WindowsProcessParameters<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows process parameters object.
    pub(super) fn new(
        vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        let inner = match kind {
            WindowsWow64Kind::Native => {
                Inner::Native(WindowsProcessParametersNative::new(vmi, va, root))
            }
            WindowsWow64Kind::X86 => Inner::X86(WindowsProcessParameters32::new(vmi, va, root)),
        };

        Self { inner }
    }

    /// Returns the current directory.
    ///
    /// This method returns the full path of the current directory
    /// for the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory`.
    pub fn current_directory(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.current_directory(),
            Inner::X86(inner) => inner.current_directory(),
        }
    }

    /// Returns the DLL search path.
    ///
    /// This method returns the list of directories that the system searches
    /// when loading DLLs for the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.DllPath`.
    pub fn dll_path(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.dll_path(),
            Inner::X86(inner) => inner.dll_path(),
        }
    }

    /// Returns the full path of the executable image.
    ///
    /// This method retrieves the full file system path of the main executable
    /// that was used to create the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.image_path_name(),
            Inner::X86(inner) => inner.image_path_name(),
        }
    }

    /// Returns the command line used to launch the process.
    ///
    /// This method retrieves the full command line string, including the
    /// executable path and any arguments, used to start the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    pub fn command_line(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.command_line(),
            Inner::X86(inner) => inner.command_line(),
        }
    }
}

/// The inner representation of a Windows process parameters object.
enum Inner<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// A native (non-WoW64) process.
    Native(WindowsProcessParametersNative<'a, Driver>),

    /// An x86 process running under WoW64.
    X86(WindowsProcessParameters32<'a, Driver>),
}

struct WindowsProcessParametersNative<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_RTL_USER_PROCESS_PARAMETERS` structure.
    va: Va,

    /// The translation root.
    root: Pa,
}

impl<'a, Driver> WindowsProcessParametersNative<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new process parameters object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Returns the current directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory`.
    fn current_directory(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let CURDIR = &offsets._CURDIR;
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.offset + CURDIR.DosPath.offset,
            self.root,
        ))
    }

    /// Returns the DLL search path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.DllPath`.
    fn dll_path(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.DllPath.offset,
            self.root,
        ))
    }

    /// Returns the image path name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    fn image_path_name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.ImagePathName.offset,
            self.root,
        ))
    }

    /// Returns the command line.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    fn command_line(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.CommandLine.offset,
            self.root,
        ))
    }
}

struct WindowsProcessParameters32<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_RTL_USER_PROCESS_PARAMETERS32` structure.
    va: Va,

    /// The translation root.
    root: Pa,
}

impl<'a, Driver> WindowsProcessParameters32<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new process parameters object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Returns the current directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS32.CurrentDirectory`.
    fn current_directory(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset: u64 = 0x24;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset,
            self.root,
        ))
    }

    /// Returns the DLL search path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS32.DllPath`.
    fn dll_path(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_DllPath_offset: u64 = 0x30;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_DllPath_offset,
            self.root,
        ))
    }

    /// Returns the image path name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS32.ImagePathName`.
    fn image_path_name(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset: u64 = 0x38;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset,
            self.root,
        ))
    }

    /// Returns the command line.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_RTL_USER_PROCESS_PARAMETERS32.CommandLine`.
    fn command_line(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset: u64 = 0x40;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset,
            self.root,
        ))
    }
}
