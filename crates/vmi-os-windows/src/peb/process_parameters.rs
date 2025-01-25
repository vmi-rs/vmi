use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState};

use super::WindowsWow64Kind;
use crate::{arch::ArchAdapter, Offsets, WindowsOs, WindowsOsExt as _};

/// A Windows process parameters object.
pub struct WindowsOsProcessParameters<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: Inner<'a, Driver>,
}

impl<'a, Driver> WindowsOsProcessParameters<'a, Driver>
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
                Inner::Native(WindowsOsProcessParametersNative::new(vmi, va, root))
            }
            WindowsWow64Kind::X86 => Inner::X86(WindowsOsProcessParameters32::new(vmi, va, root)),
        };

        Self { inner }
    }

    /// Gets the current working directory of a process.
    ///
    /// This method retrieves the full path of the current working directory
    /// for the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING CurrentDirectory = ProcessParameters->CurrentDirectory;
    /// return CurrentDirectory;
    /// ```
    pub fn current_directory(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.current_directory(),
            Inner::X86(inner) => inner.current_directory(),
        }
    }

    /// Gets the DLL search path for a process.
    ///
    /// This method retrieves the list of directories that the system searches
    /// when loading DLLs for the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING DllPath = ProcessParameters->DllPath;
    /// return DllPath;
    /// ```
    pub fn dll_path(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.dll_path(),
            Inner::X86(inner) => inner.dll_path(),
        }
    }

    /// Gets the full path of the executable image for a process.
    ///
    /// This method retrieves the full file system path of the main executable
    /// that was used to create the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING ImagePathName = ProcessParameters->ImagePathName;
    /// return ImagePathName;
    /// ```
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.image_path_name(),
            Inner::X86(inner) => inner.image_path_name(),
        }
    }

    /// Gets the command line used to launch a process.
    ///
    /// This method retrieves the full command line string, including the
    /// executable path and any arguments, used to start the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING CommandLine = ProcessParameters->CommandLine;
    /// return CommandLine;
    /// ```
    pub fn command_line(&self) -> Result<String, VmiError> {
        match &self.inner {
            Inner::Native(inner) => inner.command_line(),
            Inner::X86(inner) => inner.command_line(),
        }
    }
}

enum Inner<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    Native(WindowsOsProcessParametersNative<'a, Driver>),
    X86(WindowsOsProcessParameters32<'a, Driver>),
}

struct WindowsOsProcessParametersNative<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
    root: Pa,
}

impl<'a, Driver> WindowsOsProcessParametersNative<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    fn offsets(&self) -> &Offsets {
        self.vmi.underlying_os().offsets()
    }

    /// Retrieves the current directory for a native (non-WoW64) process.
    fn current_directory(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let CURDIR = &offsets._CURDIR;
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.offset + CURDIR.DosPath.offset,
            self.root,
        ))
    }

    /// Retrieves the DLL search path for a native (non-WoW64) process.
    fn dll_path(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.DllPath.offset,
            self.root,
        ))
    }

    /// Retrieves the image path name for a native (non-WoW64) process.
    fn image_path_name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.ImagePathName.offset,
            self.root,
        ))
    }

    /// Retrieves the command line for a native (non-WoW64) process.
    fn command_line(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let RTL_USER_PROCESS_PARAMETERS = &offsets._RTL_USER_PROCESS_PARAMETERS;

        self.vmi.os().read_unicode_string_in((
            self.va + RTL_USER_PROCESS_PARAMETERS.CommandLine.offset,
            self.root,
        ))
    }
}

struct WindowsOsProcessParameters32<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
    root: Pa,
}

impl<'a, Driver> WindowsOsProcessParameters32<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Retrieves the current directory for a 32-bit process running under
    /// WoW64.
    fn current_directory(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset: u64 = 0x24;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset,
            self.root,
        ))
    }

    /// Retrieves the DLL search path for a 32-bit process running under WoW64.
    fn dll_path(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_DllPath_offset: u64 = 0x30;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_DllPath_offset,
            self.root,
        ))
    }

    /// Retrieves the image path name for a 32-bit process running under WoW64.
    fn image_path_name(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset: u64 = 0x38;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset,
            self.root,
        ))
    }

    /// Retrieves the command line for a 32-bit process running under WoW64.
    fn command_line(&self) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset: u64 = 0x40;

        self.vmi.os().read_unicode_string32_in((
            self.va + RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset,
            self.root,
        ))
    }
}
