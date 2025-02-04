use std::str::FromStr as _;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{super::macros::impl_offsets, WindowsObject, WindowsObjectTypeKind};
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

/// A Windows object type object.
///
/// A type of kernel object managed by the Windows Object Manager.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_TYPE`.
pub struct WindowsObjectType<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_TYPE` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsObjectType<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsObjectType<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsObjectType<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsObjectType<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows directory object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the name of the object type.
    ///
    /// # Notes
    ///
    /// This method caches the object type name for this VA in the [`WindowsOs`]
    /// instance.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_TYPE.Name`.
    pub fn name(&self) -> Result<String, VmiError> {
        let os = self.vmi.underlying_os();
        if let Some(object_name) = os.object_type_name_cache.borrow().get(&self.va) {
            return Ok(object_name.clone());
        }

        let offsets = self.offsets();
        let OBJECT_TYPE = &offsets._OBJECT_TYPE;

        let object_name = self
            .vmi
            .os()
            .read_unicode_string(self.va + OBJECT_TYPE.Name.offset())?;

        os.object_type_name_cache
            .borrow_mut()
            .insert(self.va, object_name.clone());

        Ok(object_name)
    }

    /// Returns the kind of the object type.
    ///
    /// # Notes
    ///
    /// This method caches the object type kind for this VA in the [`WindowsOs`]
    /// instance.
    pub fn kind(&self) -> Result<Option<WindowsObjectTypeKind>, VmiError> {
        let os = self.vmi.underlying_os();
        if let Some(object_type) = os.object_type_cache.borrow().get(&self.va).copied() {
            return Ok(Some(object_type));
        }

        let object_type = match WindowsObjectTypeKind::from_str(&self.name()?) {
            Ok(object_type) => object_type,
            Err(_) => return Ok(None),
        };

        os.object_type_cache
            .borrow_mut()
            .insert(self.va, object_type);

        Ok(Some(object_type))
    }
}
