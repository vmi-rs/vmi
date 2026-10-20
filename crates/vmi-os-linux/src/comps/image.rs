use vmi_core::{
    Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol},
};

use crate::{ArchAdapter, LinuxOs};

/// A Linux image, an executable or shared library mapped into memory.
///
/// Images are not supported yet. Nothing creates this type, and
/// [`VmiOs::image`] returns [`VmiError::NotSupported`].
///
/// [`VmiOs::image`]: vmi_core::os::VmiOs::image
pub struct LinuxImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Base address of the image.
    va: Va,

    _marker: std::marker::PhantomData<VmiState<'a, LinuxOs<Driver>>>,
}

impl<Driver> VmiVa for LinuxImage<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for LinuxImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn base_address(&self) -> Va {
        self.va
    }

    /// Not supported yet.
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        Err(VmiError::NotSupported)
    }

    /// Not supported yet.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        Err(VmiError::NotSupported)
    }
}
