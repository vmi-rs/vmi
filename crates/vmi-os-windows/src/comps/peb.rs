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
}
