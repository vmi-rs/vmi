use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsModule};

use super::read_fixed_string;
use crate::{ArchAdapter, MacOs, offset};

/// A loaded macOS kernel extension.
///
/// # Implementation Details
///
/// Corresponds to an `OSKextLoadedKextSummary` entry in the array of
/// `gLoadedKextSummaries`.
pub struct MacOsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `OSKextLoadedKextSummary` entry.
    va: Va,
}

impl<Driver> VmiVa for MacOsModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new kernel extension from the address of its summary.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the UUID of the kernel extension.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.uuid`.
    pub fn uuid(&self) -> Result<[u8; 16], VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        let mut uuid = [0u8; 16];
        self.vmi.read(self.va + summary.uuid.offset(), &mut uuid)?;
        Ok(uuid)
    }

    /// Returns the version of the kernel extension, encoded as an
    /// `OSKextVersion`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.version`.
    pub fn version(&self) -> Result<u64, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        self.vmi.read_u64(self.va + summary.version.offset())
    }

    /// Returns the load tag, the index that `kextstat` shows.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.loadTag`.
    pub fn load_tag(&self) -> Result<u32, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        self.vmi.read_u32(self.va + summary.loadTag.offset())
    }

    /// Returns the summary flags.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.flags`.
    pub fn flags(&self) -> Result<u32, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        self.vmi.read_u32(self.va + summary.flags.offset())
    }

    /// Returns the address of the executable `__TEXT_EXEC` segment.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.text_exec_address`.
    pub fn text_exec_address(&self) -> Result<Va, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        Ok(Va(self
            .vmi
            .read_u64(self.va + summary.text_exec_address.offset())?))
    }

    /// Returns the size of the executable `__TEXT_EXEC` segment.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.text_exec_size`.
    pub fn text_exec_size(&self) -> Result<u64, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        self.vmi.read_u64(self.va + summary.text_exec_size.offset())
    }
}

impl<'a, Driver> VmiOsModule<'a, Driver> for MacOsModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the address of the Mach-O header of the kernel extension.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.address`.
    fn base_address(&self) -> Result<Va, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        Ok(Va(self.vmi.read_u64(self.va + summary.address.offset())?))
    }

    /// Returns the size of the kernel extension.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.size`.
    fn size(&self) -> Result<u64, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        self.vmi.read_u64(self.va + summary.size.offset())
    }

    /// Returns the bundle identifier of the kernel extension.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `OSKextLoadedKextSummary.name`.
    fn name(&self) -> Result<String, VmiError> {
        let summary = offset!(self.vmi, _loaded_kext_summary);

        read_fixed_string(
            self.vmi,
            self.va + summary.name.offset(),
            summary.name.size(),
        )
    }
}
