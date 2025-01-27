use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    arch::ArchAdapter,
    macros::{impl_offsets, impl_offsets_ext_v1, impl_offsets_ext_v2},
    xobject::WindowsObject,
    OffsetsExt, WindowsOs,
};

/// A Windows section object.
pub struct WindowsHandleTableEntry<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: Inner<'a, Driver>,
}

impl<Driver> From<WindowsHandleTableEntry<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsHandleTableEntry<Driver>) -> Self {
        match &value.inner {
            Inner::V1(inner) => inner.va,
            Inner::V2(inner) => inner.va,
        }
    }
}

impl<'a, Driver> WindowsHandleTableEntry<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new Windows section object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        let inner = match vmi.underlying_os().offsets().ext() {
            Some(OffsetsExt::V1(_)) => Inner::V1(WindowsHandleTableEntryV1::new(vmi, va)),
            Some(OffsetsExt::V2(_)) => Inner::V2(WindowsHandleTableEntryV2::new(vmi, va)),
            None => unimplemented!(),
        };

        Self { inner }
    }

    /// The `Object` (or `ObjectPointerBits`) field of the handle table entry.
    ///
    /// A pointer to an `_OBJECT_HEADER` structure.
    pub fn object(&self) -> Result<WindowsObject<'a, Driver>, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.object(),
            Inner::V2(inner) => inner.object(),
        }
    }

    /// The `Object` (or `ObjectPointerBits`) field of the handle table entry.
    ///
    /// A pointer to an `_OBJECT_HEADER` structure.
    pub fn attributes(&self) -> Result<u32, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.attributes(),
            Inner::V2(inner) => inner.attributes(),
        }
    }

    /// The `Object` (or `ObjectPointerBits`) field of the handle table entry.
    ///
    /// A pointer to an `_OBJECT_HEADER` structure.
    pub fn granted_access(&self) -> Result<u32, VmiError> {
        match &self.inner {
            Inner::V1(inner) => inner.granted_access(),
            Inner::V2(inner) => inner.granted_access(),
        }
    }
}

enum Inner<'a, Driver>
where
    Driver: VmiDriver,
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
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> WindowsHandleTableEntryV1<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v1!();

    /// Create a new Windows module object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// The `Object` (or `ObjectPointerBits`) field of the handle table entry.
    ///
    /// A pointer to an `_OBJECT_HEADER` structure.
    fn object(&self) -> Result<WindowsObject<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();

        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let object = self.vmi.read_field(self.va, &HANDLE_TABLE_ENTRY.Object)?;
        let object = Va(object & !OBJ_HANDLE_ATTRIBUTES);
        let object = object + OBJECT_HEADER.Body.offset;

        Ok(WindowsObject::new(self.vmi, object))
    }

    /// The `ObAttributes` (or `Attributes`) field of the handle table entry.
    fn attributes(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let attributes = self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.ObAttributes)?;
        let attributes = (attributes & OBJ_HANDLE_ATTRIBUTES) as u32;

        Ok(attributes)
    }

    /// The `GrantedAccess` (or `GrantedAccessBits`) field of the handle table entry.
    fn granted_access(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        Ok(self
            .vmi
            .read_field(self.va, &HANDLE_TABLE_ENTRY.GrantedAccess)? as u32)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
#[allow(non_camel_case_types, non_snake_case)]
struct _HANDLE_TABLE_ENTRY {
    LowValue: u64,
    HighValue: u64,
}

struct WindowsHandleTableEntryV2<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
    va: Va,
}

impl<'a, Driver> WindowsHandleTableEntryV2<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();
    impl_offsets_ext_v2!();

    /// Creates a new Windows module object.
    fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the virtual address of the object.
    fn object(&self) -> Result<WindowsObject<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let handle_table_entry = self.vmi.read_struct::<_HANDLE_TABLE_ENTRY>(self.va)?;

        let object_pointer_bits = HANDLE_TABLE_ENTRY
            .ObjectPointerBits
            .value_from(handle_table_entry.LowValue);

        let object = Va(0xffff_0000_0000_0000 | object_pointer_bits << 4);
        let object = object + OBJECT_HEADER.Body.offset;

        Ok(WindowsObject::new(self.vmi, object))
    }

    /// The `ObAttributes` (or `Attributes`) field of the handle table entry.
    fn attributes(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let handle_table_entry = self.vmi.read_struct::<_HANDLE_TABLE_ENTRY>(self.va)?;

        let attributes = HANDLE_TABLE_ENTRY
            .Attributes
            .value_from(handle_table_entry.LowValue) as u32;

        Ok(attributes)
    }

    /// The `GrantedAccess` (or `GrantedAccessBits`) field of the handle table entry.
    fn granted_access(&self) -> Result<u32, VmiError> {
        let offsets_ext = self.offsets_ext();
        let HANDLE_TABLE_ENTRY = &offsets_ext._HANDLE_TABLE_ENTRY;

        let handle_table_entry = self.vmi.read_struct::<_HANDLE_TABLE_ENTRY>(self.va)?;

        let granted_access = HANDLE_TABLE_ENTRY
            .GrantedAccessBits
            .value_from(handle_table_entry.HighValue) as u32;

        Ok(granted_access)
    }
}
