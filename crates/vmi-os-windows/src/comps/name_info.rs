use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{WindowsObject, macros::impl_offsets};
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

/// A name information for a Windows object.
///
/// This structure stores the name and directory information
/// associated with a named kernel object.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_HEADER_NAME_INFO`.
pub struct WindowsObjectHeaderNameInfo<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_HEADER_NAME_INFO` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsObjectHeaderNameInfo<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for WindowsObjectHeaderNameInfo<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let directory = self.directory();
        let name = self.name();

        f.debug_struct("WindowsObjectHeaderNameInfo")
            .field("directory", &directory)
            .field("name", &name)
            .finish()
    }
}

impl<'a, Driver> WindowsObjectHeaderNameInfo<'a, Driver>
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
    pub fn directory(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let OBJECT_HEADER_NAME_INFO = &offsets._OBJECT_HEADER_NAME_INFO;

        let directory = self
            .vmi
            .read_va_native(self.va + OBJECT_HEADER_NAME_INFO.Directory.offset())?;

        if directory.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsObject::new(self.vmi, directory)))
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
            .read_unicode_string(self.va + OBJECT_HEADER_NAME_INFO.Name.offset())
    }

    /// Constructs the full path of a named object from its name information.
    ///
    /// # Implementation Details
    pub fn full_path(&self) -> Result<String, VmiError> {
        let mut path = String::new();

        if let Some(directory) = self.directory()? {
            if let Some(directory_path) = directory.full_path()? {
                path.push_str(&directory_path);
            }

            if directory.va() != self.vmi.os().object_root_directory()?.va() {
                path.push('\\');
            }
        }

        path.push_str(&self.name()?);

        Ok(path)
    }
}
