use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows section object.
pub struct WindowsOsObjectHeaderNameInfo<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> WindowsOsObjectHeaderNameInfo<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Create a new Windows section object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    pub fn va(&self) -> Va {
        self.va
    }

    /// Extracts the `FileObject` from a `CONTROL_AREA` structure.
    pub fn directory(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let OBJECT_HEADER_NAME_INFO = &offsets._OBJECT_HEADER_NAME_INFO;

        self.vmi
            .read_va_native(self.va + OBJECT_HEADER_NAME_INFO.Directory.offset)
    }

    /// Extracts the `FileObject` from a `CONTROL_AREA` structure.
    pub fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let OBJECT_HEADER_NAME_INFO = &offsets._OBJECT_HEADER_NAME_INFO;

        self.vmi
            .os()
            .read_unicode_string(self.va + OBJECT_HEADER_NAME_INFO.Name.offset)
    }
}
