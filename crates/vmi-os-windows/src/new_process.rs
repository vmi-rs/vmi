use vmi_core::{
    os::{ProcessId, ProcessObject, VmiOsProcess},
    Architecture, Pa, VmiDriver, VmiError, VmiState,
};

use crate::{arch::ArchAdapter, WindowsOs};

pub struct WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    object: ProcessObject,
}

impl<'a, Driver> WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, object: ProcessObject) -> Self {
        Self { vmi, object }
    }
}

impl<'a, Driver> VmiOsProcess for WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn id(&self) -> Result<ProcessId, VmiError> {
        self.vmi.os().process_id(self.object)
    }

    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(self.object)
    }

    fn name(&self) -> Result<String, VmiError> {
        self.vmi.os().process_filename(self.object)
    }

    fn translation_root(&self) -> Result<Pa, VmiError> {
        self.vmi.os().process_translation_root(self.object)
    }
}
