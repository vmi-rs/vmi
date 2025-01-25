mod process_parameters;
use vmi_core::{Architecture, Pa, Va, VmiDriver, VmiError, VmiState};

pub use self::process_parameters::WindowsOsProcessParameters;
use crate::{arch::ArchAdapter, Offsets, WindowsOs, WindowsWow64Kind};

pub struct WindowsOsPeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
    root: Pa,
    kind: WindowsWow64Kind,
}

impl<'a, Driver> WindowsOsPeb<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new Windows PEB object.
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

    fn offsets(&self) -> &Offsets {
        self.vmi.underlying_os().offsets()
    }

    /// The address of this `_PEB` structure.
    pub fn process_parameters(&self) -> Result<WindowsOsProcessParameters<Driver>, VmiError> {
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
