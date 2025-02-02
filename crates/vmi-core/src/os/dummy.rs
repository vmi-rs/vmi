use super::{
    OsArchitecture, OsImageExportedSymbol, ProcessId, ProcessObject, ThreadId, ThreadObject, VmiOs,
    VmiOsImage, VmiOsMapped, VmiOsModule, VmiOsProcess, VmiOsRegion, VmiOsRegionKind, VmiOsThread,
};
use crate::{MemoryAccess, Pa, Va, VmiDriver, VmiError, VmiState, VmiVa};

/// Marker type for a missing OS implementation.
pub struct NoOS;

impl VmiVa for NoOS {
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<Driver> VmiOs<Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Process<'a> = NoOS;
    type Thread<'a> = NoOS;
    type Image<'a> = NoOS;
    type Module<'a> = NoOS;
    type Region<'a> = NoOS;
    type Mapped<'a> = NoOS;

    fn kernel_image_base(_vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn kernel_information_string(_vmi: VmiState<Driver, Self>) -> Result<String, VmiError> {
        unimplemented!()
    }

    fn kpti_enabled(_vmi: VmiState<Driver, Self>) -> Result<bool, VmiError> {
        unimplemented!()
    }

    fn modules(
        _vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'_>, VmiError>> + '_, VmiError> {
        #[expect(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn processes(
        _vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'_>, VmiError>> + '_, VmiError> {
        #[expect(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn process<'a>(
        _vmi: VmiState<'_, Driver, Self>,
        _process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn current_process<'a>(
        _vmi: VmiState<'_, Driver, Self>,
    ) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn system_process<'a>(_vmi: VmiState<'_, Driver, Self>) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn thread<'a>(
        _vmi: VmiState<'_, Driver, Self>,
        _thread: ThreadObject,
    ) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn current_thread(_vmi: VmiState<'_, Driver, Self>) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn image<'a>(
        _vmi: VmiState<'_, Driver, Self>,
        _image_base: Va,
    ) -> Result<Self::Image<'_>, VmiError> {
        unimplemented!()
    }

    fn module<'a>(
        _vmi: VmiState<'_, Driver, Self>,
        _module: Va,
    ) -> Result<Self::Module<'_>, VmiError> {
        unimplemented!()
    }

    fn region<'a>(
        _vmi: VmiState<'_, Driver, Self>,
        _region: Va,
    ) -> Result<Self::Region<'_>, VmiError> {
        unimplemented!()
    }

    fn syscall_argument(_vmi: VmiState<Driver, Self>, _index: u64) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn function_argument(_vmi: VmiState<Driver, Self>, _index: u64) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn function_return_value(_vmi: VmiState<Driver, Self>) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn last_error(_vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsImage<'_, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

    fn base_address(&self) -> Va {
        unimplemented!()
    }

    fn architecture(&self) -> Result<OsArchitecture, VmiError> {
        unimplemented!()
    }

    fn exports(&self) -> Result<Vec<OsImageExportedSymbol>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsMapped<'_, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

    fn path(&self) -> Result<Option<String>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsModule<'_, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

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

impl<'a, Driver> VmiOsProcess<'a, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

    fn id(&self) -> Result<ProcessId, VmiError> {
        unimplemented!()
    }

    fn object(&self) -> Result<ProcessObject, VmiError> {
        unimplemented!()
    }

    fn name(&self) -> Result<String, VmiError> {
        unimplemented!()
    }

    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        unimplemented!()
    }

    fn architecture(&self) -> Result<OsArchitecture, VmiError> {
        unimplemented!()
    }

    fn translation_root(&self) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        unimplemented!()
    }

    fn image_base(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs<Driver>>::Region<'_>, VmiError>>,
        VmiError,
    > {
        #[expect(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn find_region(
        &self,
        _address: Va,
    ) -> Result<Option<<Self::Os as VmiOs<Driver>>::Region<'a>>, VmiError> {
        unimplemented!()
    }

    fn is_valid_address(&self, _address: Va) -> Result<Option<bool>, VmiError> {
        unimplemented!()
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

    fn start(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn end(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        unimplemented!()
    }

    fn kind(&self) -> Result<VmiOsRegionKind<'a, Driver, Self::Os>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsThread<'_, Driver> for NoOS
where
    Driver: VmiDriver,
{
    type Os = NoOS;

    fn id(&self) -> Result<ThreadId, VmiError> {
        unimplemented!()
    }

    fn object(&self) -> Result<ThreadObject, VmiError> {
        unimplemented!()
    }
}
