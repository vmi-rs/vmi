use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{super::macros::impl_offsets, FromWindowsObject, WindowsObject, WindowsObjectTypeKind};
use crate::{ArchAdapter, DirectoryObjectIterator, WindowsOs};

/// A Windows directory object.
///
/// A directory object is a kernel-managed container that stores named objects
/// such as events, mutexes, symbolic links, and device objects.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_DIRECTORY`.
pub struct WindowsDirectoryObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_DIRECTORY` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsDirectoryObject<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsDirectoryObject<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsDirectoryObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        match object.type_kind()? {
            Some(WindowsObjectTypeKind::Directory) => Ok(Some(Self::new(object.vmi, object.va))),
            _ => Ok(None),
        }
    }
}

impl<Driver> VmiVa for WindowsDirectoryObject<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsDirectoryObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows directory object.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Iterates over the objects in the directory.
    pub fn iter(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsObject<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let offsets = self.offsets();
        let OBJECT_DIRECTORY = &offsets._OBJECT_DIRECTORY;
        let OBJECT_DIRECTORY_ENTRY = &offsets._OBJECT_DIRECTORY_ENTRY;

        Ok(DirectoryObjectIterator::new(
            self.vmi,
            self.va,
            OBJECT_DIRECTORY.HashBuckets.offset(),
            OBJECT_DIRECTORY_ENTRY.ChainLink.offset(),
            OBJECT_DIRECTORY_ENTRY.Object.offset(),
        ))
    }

    /// Performs a lookup in the directory.
    pub fn lookup(
        &self,
        needle: impl AsRef<str>,
    ) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let OBJECT_DIRECTORY = &offsets._OBJECT_DIRECTORY;
        let OBJECT_DIRECTORY_ENTRY = &offsets._OBJECT_DIRECTORY_ENTRY;

        let needle = needle.as_ref();

        for i in 0..37 {
            println!("i: {}", i);

            let hash_bucket = self
                .vmi
                .read_va_native(self.va + OBJECT_DIRECTORY.HashBuckets.offset() + i * 8)?;

            let mut entry = hash_bucket;
            while !entry.is_null() {
                println!("  entry: {}", entry);

                let object = self
                    .vmi
                    .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.Object.offset())?;
                println!("    object: {}", object);

                let hash_value = self
                    .vmi
                    .read_u32(entry + OBJECT_DIRECTORY_ENTRY.HashValue.offset())?;
                println!("    hash_value: {}", hash_value);

                let object = WindowsObject::new(self.vmi, object);

                if let Some(name) = object.name()? {
                    println!("    name: {name}");

                    if name == needle {
                        return Ok(Some(object));
                    }
                }

                entry = self
                    .vmi
                    .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.ChainLink.offset())?;
            }
        }

        Ok(None)
    }
}
