use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::WindowsOsObject;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsExt as _};

/// A Windows file object.
pub struct WindowsOsFileObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_FILE_OBJECT` structure.
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

    /// Returns the virtual address of the `_FILE_OBJECT` structure.
    pub fn va(&self) -> Va {
        self.va
    }

    /// Returns the device object associated with the file object.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_FILE_OBJECT.DeviceObject`.
    pub fn device_object(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let FILE_OBJECT = &offsets._FILE_OBJECT;

        self.vmi
            .read_va_native(self.va + FILE_OBJECT.DeviceObject.offset)
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
}
