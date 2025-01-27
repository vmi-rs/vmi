use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::WindowsObject;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows file object.
pub struct WindowsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_FILE_OBJECT` structure.
    va: Va,
}

impl<Driver> From<WindowsFileObject<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsFileObject<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> From<WindowsFileObject<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsFileObject<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> WindowsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Create a new Windows file object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the device object associated with the file object.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_FILE_OBJECT.DeviceObject`.
    pub fn device_object(&self) -> Result<WindowsObject<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let FILE_OBJECT = &offsets._FILE_OBJECT;

        let device_object = self
            .vmi
            .read_va_native(self.va + FILE_OBJECT.DeviceObject.offset)?;

        Ok(WindowsObject::new(self.vmi, device_object))
    }

    /// Returns the filename associated with the file object.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_FILE_OBJECT.FileName`.
    ///
    /// # Notes
    ///
    /// This operation might fail as the filename is allocated from paged pool.
    pub fn filename(&self) -> Result<String, VmiError> {
        let offsets = self.offsets();
        let FILE_OBJECT = &offsets._FILE_OBJECT;

        // Note that filename is allocated from paged pool,
        // so this read might fail.
        self.vmi
            .os()
            .read_unicode_string(self.va + FILE_OBJECT.FileName.offset)
    }

    /// Constructs the full path of a file from its `FILE_OBJECT`.
    ///
    /// This function first reads the `DeviceObject` field of the `FILE_OBJECT`
    /// structure. Then it reads the `ObjectNameInfo` of the `DeviceObject`
    /// and its directory. Finally, it concatenates the device directory
    /// name, device name, and file name.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    ///
    /// POBJECT_HEADER_NAME_INFO DeviceNameInfo = ObjectNameInfo(DeviceObject);
    /// POBJECT_HEADER_NAME_INFO DeviceDirectoryNameInfo = DeviceNameInfo->Directory
    ///     ? ObjectNameInfo(DeviceNameInfo->Directory)
    ///     : NULL;
    ///
    /// if (DeviceDirectoryNameInfo->Name != NULL) {
    ///     FullPath += '\\' + DeviceDirectoryNameInfo->Name;
    /// }
    ///
    /// if (DeviceNameInfo->Name != NULL) {
    ///     FullPath += '\\' + DeviceNameInfo->Name;
    /// }
    ///
    /// FullPath += FileObject->FileName;
    ///
    /// return FullPath;
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the provided object is not a file object.
    pub fn full_path(&self) -> Result<String, VmiError> {
        let device = self.device_object()?.name_info()?;
        let directory = match &device {
            Some(device) => match device.directory()? {
                Some(directory) => directory.name_info()?,
                None => None,
            },
            None => None,
        };

        let mut result = String::new();
        if let Some(directory) = directory {
            result.push('\\');
            result.push_str(&directory.name()?);
        }

        if let Some(device) = device {
            result.push('\\');
            result.push_str(&device.name()?);
        }

        result.push_str(&self.filename()?);

        Ok(result)
    }
}
