use vmi_core::{
    Architecture, Va, VmiError, VmiVa,
    driver::VmiRead,
    os::{
        ThreadId, ThreadObject, VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol, VmiOsMapped,
        VmiOsModule, VmiOsThread,
    },
};

use crate::{LinuxOs, arch::ArchAdapter};

/// Dummy implementation for Linux OS image.
pub struct LinuxImage;

impl VmiVa for LinuxImage {
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for LinuxImage
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn base_address(&self) -> Va {
        unimplemented!()
    }

    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        unimplemented!()
    }

    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        unimplemented!()
    }
}

/// Dummy implementation for Linux OS mapped memory.
pub struct LinuxMapped;

impl VmiVa for LinuxMapped {
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<Driver> VmiOsMapped<'_, Driver> for LinuxMapped
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn path(&self) -> Result<Option<String>, VmiError> {
        unimplemented!()
    }
}

/// Dummy implementation for Linux OS kernel module.
pub struct LinuxModule;

impl VmiVa for LinuxModule {
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<Driver> VmiOsModule<'_, Driver> for LinuxModule
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn base_address(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn size(&self) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn name(&self) -> Result<String, VmiError> {
        unimplemented!()
    }
}

/// Dummy implementation for Linux OS thread.
pub struct LinuxThread;

impl VmiVa for LinuxThread {
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for LinuxThread
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    fn id(&self) -> Result<ThreadId, VmiError> {
        unimplemented!()
    }

    fn object(&self) -> Result<ThreadObject, VmiError> {
        unimplemented!()
    }
}
