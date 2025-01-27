mod process_parameters;
use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState};

pub use self::process_parameters::WindowsOsProcessParameters;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs};

/// The address space type in a WoW64 process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsWow64Kind {
    /// Native address space.
    Native = 0,

    /// x86 (32-bit) address space under WoW64.
    X86 = 1,
    // Arm32 = 2,
    // Amd64 = 3,
    // ChpeX86 = 4,
    // VsmEnclave = 5,
}

/// A Windows PEB structure.
pub struct WindowsOsPeb<'a, Driver>
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

impl<Driver> From<WindowsOsPeb<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsPeb<Driver>) -> Self {
        value.va
    }
}

impl<Driver> std::fmt::Debug for WindowsOsPeb<'_, Driver>
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

impl<'a, Driver> WindowsOsPeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows PEB object.
    pub(super) fn new(
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

    /// The address of this `_PEB` structure.
    pub fn process_parameters(&self) -> Result<WindowsOsProcessParameters<'a, Driver>, VmiError> {
        let va = match self.kind {
            WindowsWow64Kind::Native => {
                let offsets = self.offsets();
                let PEB = &offsets.common._PEB;

                self.vmi
                    .read_va_native_in((self.va + PEB.ProcessParameters.offset, self.root))?
            }
            WindowsWow64Kind::X86 => {
                const PEB32_ProcessParameters_offset: u64 = 0x10;

                self.vmi
                    .read_va_native_in((self.va + PEB32_ProcessParameters_offset, self.root))?
            }
        };

        Ok(WindowsOsProcessParameters::new(
            self.vmi, va, self.root, self.kind,
        ))
    }
}
