use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{FromWindowsObject, WindowsObject, WindowsObjectTypeKind};
use crate::{ArchAdapter, WindowsError, WindowsOs, WindowsOsExt as _, offset};

/// The flag of a symbolic link that resolves through a callback.
///
/// `ObCreateSymbolicLink` sets it in `_OBJECT_SYMBOLIC_LINK.Flags`, and
/// `NtQuerySymbolicLinkObject` returns an empty target for such a link. The
/// name comes from
/// <https://windows-internals.com/dkom-now-with-symbolic-links/>.
const OBJECT_SYMBOLIC_LINK_USE_CALLBACK: u32 = 0x10;

/// A Windows symbolic link object.
///
/// A symbolic link object maps a name in the object namespace to another
/// path, for example a drive letter in `\GLOBAL??` to a device in `\Device`.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_SYMBOLIC_LINK`.
pub struct WindowsSymbolicLinkObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_OBJECT_SYMBOLIC_LINK` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsSymbolicLinkObject<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsSymbolicLinkObject<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsSymbolicLinkObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        match object.type_kind()? {
            Some(WindowsObjectTypeKind::SymbolicLink) => Ok(Some(Self::new(object.vmi, object.va))),
            _ => Ok(None),
        }
    }
}

impl<Driver> VmiVa for WindowsSymbolicLinkObject<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSymbolicLinkObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows symbolic link object.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the target of the symbolic link, such as
    /// `\Device\HarddiskVolume2` for `\GLOBAL??\C:`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_SYMBOLIC_LINK.LinkTarget`.
    ///
    /// # Notes
    ///
    /// This operation might fail as the target is allocated from paged pool.
    ///
    /// From Windows 10 1703 on, a link can resolve through a callback, whose
    /// pointer shares the offset of `LinkTarget`. Such a link has no target,
    /// and this operation fails for it with [`VmiError::NotSupported`].
    pub fn link_target(&self) -> Result<String, VmiError> {
        let OBJECT_SYMBOLIC_LINK = offset!(self.vmi, _OBJECT_SYMBOLIC_LINK);

        if let Some(Flags) = &OBJECT_SYMBOLIC_LINK.Flags {
            let flags = self.vmi.read_u32(self.va + Flags.offset())?;
            if flags & OBJECT_SYMBOLIC_LINK_USE_CALLBACK != 0 {
                return Err(VmiError::NotSupported);
            }
        }

        self.vmi
            .os()
            .read_unicode_string(self.va + OBJECT_SYMBOLIC_LINK.LinkTarget.offset())
    }

    /// Returns the drive index of the symbolic link: 1 for `A:` to 26 for
    /// `Z:`, or 0 for a link that defines no drive letter.
    ///
    /// The kernel sets the index when it creates a link named `X:` in an
    /// object directory that has a device map, such as `\GLOBAL??`, and
    /// clears it when it deletes the link's name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_SYMBOLIC_LINK.DosDeviceDriveIndex`.
    pub fn drive_index(&self) -> Result<u32, VmiError> {
        let OBJECT_SYMBOLIC_LINK = offset!(self.vmi, _OBJECT_SYMBOLIC_LINK);

        self.vmi
            .read_u32(self.va + OBJECT_SYMBOLIC_LINK.DosDeviceDriveIndex.offset())
    }

    /// Returns the drive letter that the symbolic link defines, such as `C`
    /// for `\GLOBAL??\C:`, or `None` for a link that defines no drive letter.
    ///
    /// The letter comes from the [`drive_index`]. An index above 26 gives
    /// [`WindowsError::CorruptedStruct`].
    ///
    /// [`drive_index`]: Self::drive_index
    pub fn drive_letter(&self) -> Result<Option<char>, VmiError> {
        match self.drive_index()? {
            0 => Ok(None),
            index @ 1..=26 => Ok(Some(char::from(b'A' + (index - 1) as u8))),
            _ => Err(
                WindowsError::CorruptedStruct("OBJECT_SYMBOLIC_LINK.DosDeviceDriveIndex").into(),
            ),
        }
    }
}
