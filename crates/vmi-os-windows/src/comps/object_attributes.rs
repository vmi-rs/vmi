use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _, offset};

/// A Windows object attributes.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_ATTRIBUTES`.
pub struct WindowsObjectAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_OBJECT_ATTRIBUTES` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsObjectAttributes<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsObjectAttributes<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows object attributes.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the root directory handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_ATTRIBUTES.RootDirectory`.
    pub fn root_directory(&self) -> Result<Va, VmiError> {
        let OBJECT_ATTRIBUTES = offset!(self.vmi, _OBJECT_ATTRIBUTES);

        self.vmi
            .read_va_native(self.va + OBJECT_ATTRIBUTES.RootDirectory.offset())
    }

    /// Returns the root directory handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_ATTRIBUTES.ObjectName`.
    pub fn object_name(&self) -> Result<Option<String>, VmiError> {
        let OBJECT_ATTRIBUTES = offset!(self.vmi, _OBJECT_ATTRIBUTES);

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
        let OBJECT_ATTRIBUTES = offset!(self.vmi, _OBJECT_ATTRIBUTES);

        self.vmi
            .read_u32(self.va + OBJECT_ATTRIBUTES.Attributes.offset())
    }
}
