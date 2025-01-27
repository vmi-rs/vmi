use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::WindowsOsObject;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows object header name info.
pub struct WindowsOsObjectHeaderNameInfo<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_HEADER_NAME_INFO` structure.
    va: Va,
}

impl<Driver> From<WindowsOsObjectHeaderNameInfo<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsObjectHeaderNameInfo<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> WindowsOsObjectHeaderNameInfo<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows object header name info.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the directory object associated with the object name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_HEADER_NAME_INFO.Directory`.
    pub fn directory(&self) -> Result<Option<WindowsOsObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let OBJECT_HEADER_NAME_INFO = &offsets._OBJECT_HEADER_NAME_INFO;

        let directory = self
            .vmi
            .read_va_native(self.va + OBJECT_HEADER_NAME_INFO.Directory.offset)?;

        if directory.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsOsObject::new(self.vmi, directory)))
    }

    /// Returns the name of the object.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_HEADER_NAME_INFO.Name`.
    pub fn name(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let OBJECT_HEADER_NAME_INFO = &offsets._OBJECT_HEADER_NAME_INFO;

        self.vmi
            .os()
            .read_unicode_string(self.va + OBJECT_HEADER_NAME_INFO.Name.offset)
    }
}
