use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::WindowsOsObject;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows file object.
pub struct WindowsOsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> From<WindowsOsFileObject<'a, Driver>> for WindowsOsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsFileObject<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> WindowsOsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Create a new Windows file object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    pub fn va(&self) -> Va {
        self.va
    }

    /// Extracts the `DeviceObject` from a `FILE_OBJECT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    /// return DeviceObject;
    /// ```
    pub fn device_object(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let FILE_OBJECT = &offsets._FILE_OBJECT;

        self.vmi
            .read_va_native(self.va + FILE_OBJECT.DeviceObject.offset)
    }

    /// Extracts the `FileName` from a `FILE_OBJECT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// UNICODE_STRING FileName = FileObject->FileName;
    /// return FileName;
    /// ```
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
}
