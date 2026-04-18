use super::{
    ProcessId, ProcessObject, ThreadId, ThreadObject, VmiOs, VmiOsImage, VmiOsImageArchitecture,
    VmiOsImageSymbol, VmiOsMapped, VmiOsModule, VmiOsProcess, VmiOsRegion, VmiOsRegionKind,
    VmiOsThread,
};
use crate::{MemoryAccess, Pa, Va, VmiDriver, VmiError, VmiState, VmiVa, os::VmiOsUserModule};

/// Marker type for a missing OS implementation.
pub struct NoOS<Driver>(pub std::marker::PhantomData<Driver>)
where
    Driver: VmiDriver;

impl<Driver> VmiVa for NoOS<Driver>
where
    Driver: VmiDriver,
{
    fn va(&self) -> Va {
        unimplemented!()
    }
}

impl<Driver> VmiOs for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Architecture = Driver::Architecture;
    type Driver = Driver;

    type Process<'a> = NoOS<Driver>;
    type Thread<'a> = NoOS<Driver>;
    type Image<'a> = NoOS<Driver>;
    type Module<'a> = NoOS<Driver>;
    type UserModule<'a> = NoOS<Driver>;
    type Region<'a> = NoOS<Driver>;
    type Mapped<'a> = NoOS<Driver>;

    fn kernel_image_base(_vmi: VmiState<Self>) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn kernel_information_string(_vmi: VmiState<Self>) -> Result<String, VmiError> {
        unimplemented!()
    }

    fn kpti_enabled(_vmi: VmiState<Self>) -> Result<bool, VmiError> {
        unimplemented!()
    }

    fn modules<'a>(
        _vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        #[allow(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn processes<'a>(
        _vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        #[allow(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn process<'a>(
        _vmi: VmiState<'_, Self>,
        _process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn current_process<'a>(_vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn system_process<'a>(_vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        unimplemented!()
    }

    fn thread<'a>(
        _vmi: VmiState<'_, Self>,
        _thread: ThreadObject,
    ) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn current_thread(_vmi: VmiState<'_, Self>) -> Result<Self::Thread<'_>, VmiError> {
        unimplemented!()
    }

    fn image<'a>(_vmi: VmiState<'_, Self>, _image_base: Va) -> Result<Self::Image<'_>, VmiError> {
        unimplemented!()
    }

    fn module<'a>(_vmi: VmiState<'_, Self>, _module: Va) -> Result<Self::Module<'_>, VmiError> {
        unimplemented!()
    }

    fn user_module<'a>(
        _vmi: VmiState<'_, Self>,
        _module: Va,
        _root: Pa,
    ) -> Result<Self::UserModule<'_>, VmiError> {
        unimplemented!()
    }

    fn region<'a>(_vmi: VmiState<'_, Self>, _region: Va) -> Result<Self::Region<'_>, VmiError> {
        unimplemented!()
    }

    fn syscall_argument(_vmi: VmiState<Self>, _index: u64) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn function_argument(_vmi: VmiState<Self>, _index: u64) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn function_return_value(_vmi: VmiState<Self>) -> Result<u64, VmiError> {
        unimplemented!()
    }

    fn last_error(_vmi: VmiState<Self>) -> Result<Option<u32>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsImage<'_, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

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

impl<Driver> VmiOsMapped<'_, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

    fn path(&self) -> Result<Option<String>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsModule<'_, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

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

impl<Driver> VmiOsUserModule<'_, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

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

impl<'a, Driver> VmiOsProcess<'a, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

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

    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError> {
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
        impl Iterator<Item = Result<<Self::Os as VmiOs>::Region<'a>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        #[allow(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn find_region(
        &self,
        _address: Va,
    ) -> Result<Option<<Self::Os as VmiOs>::Region<'a>>, VmiError> {
        unimplemented!()
    }

    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs>::Thread<'a>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        #[allow(unreachable_code)]
        {
            unimplemented!() as Result<std::iter::Empty<_>, VmiError>
        }
    }

    fn is_valid_address(&self, _address: Va) -> Result<Option<bool>, VmiError> {
        unimplemented!()
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

    fn start(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn end(&self) -> Result<Va, VmiError> {
        unimplemented!()
    }

    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        unimplemented!()
    }

    fn kind(&self) -> Result<VmiOsRegionKind<'a, Self::Os>, VmiError> {
        unimplemented!()
    }
}

impl<Driver> VmiOsThread<'_, Driver> for NoOS<Driver>
where
    Driver: VmiDriver,
{
    type Os = NoOS<Driver>;

    fn id(&self) -> Result<ThreadId, VmiError> {
        unimplemented!()
    }

    fn object(&self) -> Result<ThreadObject, VmiError> {
        unimplemented!()
    }
}
