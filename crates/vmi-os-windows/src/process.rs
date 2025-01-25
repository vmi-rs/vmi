use vmi_core::{
    os::{OsArchitecture, ProcessId, ProcessObject, VmiOsProcess},
    Architecture, Pa, Va, VmiDriver, VmiError, VmiState,
};

use crate::{
    arch::ArchAdapter, macros::impl_offsets, peb::WindowsOsPeb, region::WindowsOsRegion,
    OffsetsExt, TreeNodeIterator, WindowsOs, WindowsOsExt as _, WindowsWow64Kind,
};

/// A Windows OS process.
pub struct WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows OS process.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, process: ProcessObject) -> Self {
        Self { vmi, va: process.0 }
    }

    pub fn peb(&self) -> Result<WindowsOsPeb<Driver>, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let root = self.translation_root()?;

        let wow64 = self
            .vmi
            .read_va_native(self.va + EPROCESS.WoW64Process.offset)?;

        if wow64.is_null() {
            let peb64 = self.vmi.read_va_native(self.va + EPROCESS.Peb.offset)?;

            Ok(WindowsOsPeb::new(
                self.vmi,
                peb64,
                root,
                WindowsWow64Kind::Native,
            ))
        }
        else {
            let peb32 = match &offsets.ext {
                Some(OffsetsExt::V1(_)) => wow64,
                Some(OffsetsExt::V2(v2)) => self
                    .vmi
                    .read_va_native(wow64 + v2._EWOW64PROCESS.Peb.offset)?,
                None => panic!("OffsetsExt not set"),
            };

            Ok(WindowsOsPeb::new(
                self.vmi,
                peb32,
                root,
                WindowsWow64Kind::X86,
            ))
        }
    }
}

impl<'a, Driver> VmiOsProcess for WindowsOsProcess<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn id(&self) -> Result<ProcessId, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let result = self
            .vmi
            .read_u32(self.va + EPROCESS.UniqueProcessId.offset)?;

        Ok(ProcessId(result))
    }

    fn object(&self) -> Result<ProcessObject, VmiError> {
        Ok(ProcessObject(self.va))
    }

    fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        self.vmi
            .read_string(self.va + EPROCESS.ImageFileName.offset)
    }

    fn parent_id(&self) -> Result<ProcessId, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let result = self
            .vmi
            .read_u32(self.va + EPROCESS.InheritedFromUniqueProcessId.offset)?;

        Ok(ProcessId(result))
    }

    fn architecture(&self) -> Result<OsArchitecture, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        let wow64process = self
            .vmi
            .read_va_native(self.va + EPROCESS.WoW64Process.offset)?;

        if wow64process.is_null() {
            Ok(OsArchitecture::Amd64)
        }
        else {
            Ok(OsArchitecture::X86)
        }
    }

    fn translation_root(&self) -> Result<Pa, VmiError> {
        self.vmi.os().process_translation_root(self.object()?)
    }

    fn user_translation_root(&self) -> Result<Pa, VmiError> {
        self.vmi.os().process_user_translation_root(self.object()?)
    }

    fn image_base(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let EPROCESS = &offsets._EPROCESS;

        self.vmi
            .read_va_native(self.va + EPROCESS.SectionBaseAddress.offset)
    }

    #[expect(refining_impl_trait)]
    fn regions(
        &self,
    ) -> Result<impl Iterator<Item = Result<WindowsOsRegion<Driver>, VmiError>>, VmiError> {
        let root = self.vmi.os().vad_root(self.object()?)?;

        Ok(TreeNodeIterator::new(self.vmi, root)?
            .map(|result| result.map(|vad| WindowsOsRegion::new(self.vmi, vad))))
    }

    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError> {
        self.vmi
            .os()
            .process_address_is_valid(self.object()?, address)
    }
}
