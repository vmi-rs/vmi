use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{
    WindowsObject,
    macros::{impl_offsets, impl_offsets_ext_v1, impl_offsets_ext_v2},
};
use crate::{ArchAdapter, OffsetsExt, WindowsOs};

/// A Windows handle table entry.
///
/// A handle table entry maps a handle to a kernel object
/// within the process's handle table.
///
/// # Implementation Details
///
/// Corresponds to `_HANDLE_TABLE_ENTRY`.
pub struct WindowsHandleTableEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: Inner<'a, Driver>,
}

impl<Driver> VmiVa for WindowsHandleTableEntry<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        match &self.inner {
            Inner::V1(inner) => inner.va,
            Inner::V2(inner) => inner.va,
        }
    }
}

impl<'a, Driver> WindowsHandleTableEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new Windows handle table entry.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        let inner = match vmi.underlying_os().offsets.ext() {
            Some(OffsetsExt::V1(_)) => Inner::V1(WindowsHandleTableEntryV1::new(vmi, va)),
            Some(OffsetsExt::V2(_)) => Inner::V2(WindowsHandleTableEntryV2::new(vmi, va)),
            None => unimplemented!(),
        };

        Self { inner }
    }

    /// Returns the object associated with this handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_OBJECT_HEADER.Object` or `_OBJECT_HEADER.ObjectPointerBits`.
    pub fn object(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.object(),
            Inner::V2(inner) => inner.object(),
        }
    }

    /// Returns the handle attributes.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HANDLE_TABLE_ENTRY.ObAttributes` or `_HANDLE_TABLE_ENTRY.Attributes`.
    pub fn attributes(&self) -> Result<u32, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.attributes(),
            Inner::V2(inner) => inner.attributes(),
        }
    }

    /// Returns the granted access rights for this handle.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_HANDLE_TABLE_ENTRY.GrantedAccess` or `_HANDLE_TABLE_ENTRY.GrantedAccessBits`.
    pub fn granted_access(&self) -> Result<u32, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.granted_access(),
            Inner::V2(inner) => inner.granted_access(),
        }
    }
}

enum Inner<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    V1(WindowsHandleTableEntryV1<'a, Driver>),
    V2(WindowsHandleTableEntryV2<'a, Driver>),
}

const OBJ_PROTECT_CLOSE: u64 = 0x00000001;
const OBJ_INHERIT: u64 = 0x00000002;
const OBJ_AUDIT_OBJECT_CLOSE: u64 = 0x00000004;
const OBJ_HANDLE_ATTRIBUTES: u64 = OBJ_PROTECT_CLOSE | OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE;

struct WindowsHandleTableEntryV1<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_HANDLE_TABLE_ENTRY` structure.
    va: Va,
}

impl<'a, Driver> WindowsHandleTableEntryV1<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v1!();

    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    fn object(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();

        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let object = self.vmi.read_field(self.va, &HANDLE_TABLE_ENTRY.Object)?;
        let object = Va(object & !OBJ_HANDLE_ATTRIBUTES);

        if object.is_null() {
            return Ok(None);
        }

        let object = object + OBJECT_HEADER.Body.offset();

        Ok(Some(WindowsObject::new(self.vmi, object)))
    }

    fn attributes(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let attributes = self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.ObAttributes)?;
        let attributes = (attributes & OBJ_HANDLE_ATTRIBUTES) as u32;

        Ok(attributes)
    }

    fn granted_access(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        Ok(self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.GrantedAccess)? as u32)
    }
}

struct WindowsHandleTableEntryV2<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_HANDLE_TABLE_ENTRY` structure.
    va: Va,
}

impl<'a, Driver> WindowsHandleTableEntryV2<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v2!();

    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    fn object(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let object_pointer_bits = self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.ObjectPointerBits)?;

        let object_pointer_bits = HANDLE_TABLE_ENTRY
            .ObjectPointerBits
            .extract(object_pointer_bits);

        if object_pointer_bits == 0 {
            return Ok(None);
        }

        let object = Va(0xffff_0000_0000_0000 | (object_pointer_bits << 4));
        let object = object + OBJECT_HEADER.Body.offset();

        Ok(Some(WindowsObject::new(self.vmi, object)))
    }

    fn attributes(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let attributes = self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.Attributes)?;

        Ok(HANDLE_TABLE_ENTRY.Attributes.extract(attributes) as u32)
    }

    fn granted_access(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let granted_access = self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.GrantedAccessBits)?;

        Ok(HANDLE_TABLE_ENTRY.GrantedAccessBits.extract(granted_access) as u32)
    }
}
