use vmi_core::{Pa, Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsUserModule};

use super::MacOsImage;
use crate::{ArchAdapter, MacOs, MacOsExt as _};

/// Offset of `dyld_image_info.imageLoadAddress` from `<mach-o/dyld_images.h>`.
const IMAGE_LOAD_ADDRESS_OFFSET: u64 = 0;

/// Offset of `dyld_image_info.imageFilePath` from `<mach-o/dyld_images.h>`.
const IMAGE_FILE_PATH_OFFSET: u64 = 8;

/// Offset of `dyld_image_info.imageFileModDate` from `<mach-o/dyld_images.h>`.
const IMAGE_FILE_MOD_DATE_OFFSET: u64 = 16;

/// Upper bound on the length of an image path, in bytes.
///
/// Matches `PATH_MAX` of macOS.
const MAX_PATH_LENGTH: usize = 1024;

/// An image loaded by dyld into a macOS process.
///
/// # Implementation Details
///
/// Corresponds to a `struct dyld_image_info` entry of the `infoArray` of
/// `struct dyld_all_image_infos`, both declared in `<mach-o/dyld_images.h>`.
/// These structures live in the address space of the process.
pub struct MacOsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct dyld_image_info`.
    va: Va,

    /// Translation root of the process.
    root: Pa,
}

impl<Driver> VmiVa for MacOsUserModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new user module from the address of its
    /// `struct dyld_image_info` in the address space rooted at `root`.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Returns the path of the image as dyld loaded it.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dyld_image_info.imageFilePath`.
    pub fn path(&self) -> Result<String, VmiError> {
        let path = self
            .vmi
            .os()
            .read_pointer_in((self.va + IMAGE_FILE_PATH_OFFSET, self.root))?;

        self.vmi
            .read_string_limited_in((path, self.root), MAX_PATH_LENGTH)
    }

    /// Returns the modification time of the image file, in seconds since
    /// the Unix epoch.
    ///
    /// Images loaded from the dyld shared cache report zero.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dyld_image_info.imageFileModDate`.
    pub fn modification_date(&self) -> Result<u64, VmiError> {
        self.vmi
            .read_u64_in((self.va + IMAGE_FILE_MOD_DATE_OFFSET, self.root))
    }

    /// Returns the Mach-O image of the module.
    pub fn image(&self) -> Result<MacOsImage<'a, Driver>, VmiError> {
        Ok(MacOsImage::new(self.vmi, self.base_address()?, self.root))
    }
}

impl<'a, Driver> VmiOsUserModule<'a, Driver> for MacOsUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the address of the Mach-O header of the image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dyld_image_info.imageLoadAddress`.
    fn base_address(&self) -> Result<Va, VmiError> {
        self.vmi
            .os()
            .read_pointer_in((self.va + IMAGE_LOAD_ADDRESS_OFFSET, self.root))
    }

    /// Returns the size of the image.
    ///
    /// See [`MacOsImage::size`] for which segments count.
    fn size(&self) -> Result<u64, VmiError> {
        self.image()?.size()
    }

    /// Returns the file name of the image, the last component of
    /// [`path`](Self::path).
    fn name(&self) -> Result<String, VmiError> {
        let path = self.path()?;

        match path.rsplit_once('/') {
            Some((_, name)) => Ok(String::from(name)),
            None => Ok(path),
        }
    }
}
