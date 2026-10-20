use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsUserModule};

use crate::{ArchAdapter, LinuxOs};

/// A Linux user-mode module, a shared library loaded into a process.
///
/// User-mode modules are not supported yet. Nothing creates this type, and
/// [`VmiOs::user_module`] returns [`VmiError::NotSupported`].
///
/// [`VmiOs::user_module`]: vmi_core::os::VmiOs::user_module
pub struct LinuxUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Address of the module.
    va: Va,

    _marker: std::marker::PhantomData<VmiState<'a, LinuxOs<Driver>>>,
}

impl<Driver> VmiVa for LinuxUserModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> VmiOsUserModule<'a, Driver> for LinuxUserModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Not supported yet.
    fn base_address(&self) -> Result<Va, VmiError> {
        Err(VmiError::NotSupported)
    }

    /// Not supported yet.
    fn size(&self) -> Result<u64, VmiError> {
        Err(VmiError::NotSupported)
    }

    /// Not supported yet.
    fn name(&self) -> Result<String, VmiError> {
        Err(VmiError::NotSupported)
    }
}
