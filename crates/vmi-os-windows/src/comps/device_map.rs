use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, WindowsOs, offset};

/// A Windows device map.
///
/// A device map belongs to an object directory that holds DOS device names,
/// such as `\GLOBAL??`, and lists the drive letters that the directory
/// defines.
///
/// # Implementation Details
///
/// Corresponds to `_DEVICE_MAP`.
pub struct WindowsDeviceMap<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_DEVICE_MAP` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsDeviceMap<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsDeviceMap<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows device map.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the drive letters of the map as a bit mask: bit 0 for `A:` to
    /// bit 25 for `Z:`.
    ///
    /// The kernel sets a letter's bit when it creates the letter's symbolic
    /// link in the map's directory, and clears it when it deletes the link's
    /// name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_DEVICE_MAP.DriveMap`.
    pub fn drive_map(&self) -> Result<u32, VmiError> {
        let DEVICE_MAP = offset!(self.vmi, _DEVICE_MAP);

        self.vmi.read_u32(self.va + DEVICE_MAP.DriveMap.offset())
    }

    /// Returns the drive letters of the map in alphabetical order, such as
    /// `C` and `D`.
    ///
    /// The letters come from the [`drive_map`]: bit 0 is `A` and bit 25 is
    /// `Z`.
    ///
    /// [`drive_map`]: Self::drive_map
    pub fn drive_letters(&self) -> Result<impl Iterator<Item = char> + use<'a, Driver>, VmiError> {
        let drive_map = self.drive_map()?;

        Ok((0..26u8)
            .filter(move |bit| drive_map & (1 << bit) != 0)
            .map(|bit| char::from(b'A' + bit)))
    }
}
