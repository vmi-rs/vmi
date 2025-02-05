use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{macros::impl_offsets, process_parameters::WindowsProcessParameters};
use crate::{ArchAdapter, WindowsOs};

/// The address space type in a WoW64 process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsWow64Kind {
    /// Native address space.
    Native = 0,

    /// x86 (32-bit) address space under WoW64.
    X86 = 1,
    // Arm32 = 2,
    // Amd64 = 3,
    // ChpeX86 = 4,
    // VsmEnclave = 5,
}

/// A Windows process environment block (PEB).
///
/// The PEB is a user-mode structure that stores process-wide information,
/// such as loaded modules, heap data, and environment settings.
/// This structure supports both **32-bit and 64-bit** PEBs.
///
/// # Implementation Details
///
/// Corresponds to `_PEB`.
pub struct WindowsPeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_PEB` structure.
    va: Va,

    /// The translation root.
    root: Pa,

    /// The kind of the process.
    kind: WindowsWow64Kind,
}

impl<Driver> VmiVa for WindowsPeb<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for WindowsPeb<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let process_parameters = self.process_parameters();

        f.debug_struct("WindowsOsPeb")
            .field("process_parameters", &process_parameters)
            .finish()
    }
}

impl<'a, Driver> WindowsPeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows PEB object.
    pub fn new(
        vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
        va: Va,
        root: Pa,
        kind: WindowsWow64Kind,
    ) -> Self {
        Self {
            vmi,
            va,
            root,
            kind,
        }
    }

    /// Returns the process parameters of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_PEB.ProcessParameters`.
    pub fn process_parameters(&self) -> Result<WindowsProcessParameters<'a, Driver>, VmiError> {
        let va = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let PEB = &offsets.common._PEB;

                self.vmi
                    .read_va_native_in((self.va + PEB.ProcessParameters.offset(), self.root))?
            }
            WindowsWow64Kind::X86 => {
                const PEB32_ProcessParameters_offset: u64 = 0x10;

                self.vmi
                    .read_va_native_in((self.va + PEB32_ProcessParameters_offset, self.root))?
            }
        };

        Ok(WindowsProcessParameters::new(
            self.vmi, va, self.root, self.kind,
        ))
    }

    /// Returns the current directory.
    ///
    /// Shortcut for [`self.process_parameters()?.current_directory()`].
    ///
    /// [`self.process_parameters()?.current_directory()`]: WindowsProcessParameters::current_directory
    pub fn current_directory(&self) -> Result<String, VmiError> {
        self.process_parameters()?.current_directory()
    }

    /// Returns the DLL search path.
    ///
    /// Shortcut for [`self.process_parameters()?.dll_path()`].
    ///
    /// [`self.process_parameters()?.dll_path()`]: WindowsProcessParameters::dll_path
    pub fn dll_path(&self) -> Result<String, VmiError> {
        self.process_parameters()?.dll_path()
    }

    /// Returns the full path of the executable image.
    ///
    /// Shortcut for [`self.process_parameters()?.image_path_name()`].
    ///
    /// [`self.process_parameters()?.image_path_name()`]: WindowsProcessParameters::image_path_name
    pub fn image_path_name(&self) -> Result<String, VmiError> {
        self.process_parameters()?.image_path_name()
    }

    /// Returns the command line used to launch the process.
    ///
    /// Shortcut for [`self.process_parameters()?.command_line()`].
    ///
    /// [`self.process_parameters()?.command_line()`]: WindowsProcessParameters::command_line
    pub fn command_line(&self) -> Result<String, VmiError> {
        self.process_parameters()?.command_line()
    }
}
