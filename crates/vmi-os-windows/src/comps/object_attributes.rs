use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::macros::impl_offsets;
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

/// A Windows object attributes.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_ATTRIBUTES`.
pub struct WindowsObjectAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_ATTRIBUTES` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsObjectAttributes<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsObjectAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows object attributes.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the root directory handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_ATTRIBUTES.RootDirectory`.
    pub fn root_directory(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let OBJECT_ATTRIBUTES = &offsets._OBJECT_ATTRIBUTES;

        self.vmi
            .read_va_native(self.va + OBJECT_ATTRIBUTES.RootDirectory.offset())
    }

    /// Returns the root directory handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_ATTRIBUTES.ObjectName`.
    pub fn object_name(&self) -> Result<Option<String>, VmiError> {
        let offsets = self.offsets();
        let OBJECT_ATTRIBUTES = &offsets._OBJECT_ATTRIBUTES;

        let object_name = self
            .vmi
            .read_va_native(self.va + OBJECT_ATTRIBUTES.ObjectName.offset())?;

        if object_name.is_null() {
            return Ok(None);
        }

        Ok(Some(self.vmi.os().read_unicode_string(object_name)?))
    }

    /// Returns the attributes.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_ATTRIBUTES.Attributes`.
    pub fn attributes(&self) -> Result<u32, VmiError> {
        let offsets = self.offsets();
        let OBJECT_ATTRIBUTES = &offsets._OBJECT_ATTRIBUTES;

        self.vmi
            .read_u32(self.va + OBJECT_ATTRIBUTES.Attributes.offset())
    }
}
