use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{super::macros::impl_offsets, WindowsObject};
use crate::{ArchAdapter, WindowsOs};

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
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_OBJECT_DIRECTORY` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsDirectoryObject<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsDirectoryObject<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsDirectoryObject<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsDirectoryObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows directory object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Iterates over the objects in the directory.
    pub fn iter(
        &self,
    ) -> Result<impl Iterator<Item = Result<WindowsObject<'a, Driver>, VmiError>>, VmiError> {
        let offsets = self.offsets();
        let OBJECT_DIRECTORY = &offsets._OBJECT_DIRECTORY;
        let OBJECT_DIRECTORY_ENTRY = &offsets._OBJECT_DIRECTORY_ENTRY;

        let mut entries = Vec::new();

        for i in 0..37 {
            let hash_bucket = self
                .vmi
                .read_va_native(self.va + OBJECT_DIRECTORY.HashBuckets.offset() + i * 8)?;

            let mut entry = hash_bucket;
            while !entry.is_null() {
                let object = self
                    .vmi
                    .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.Object.offset())?;

                let object = WindowsObject::new(self.vmi, object);

                entries.push(Ok(object));

                entry = self
                    .vmi
                    .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.ChainLink.offset())?;
            }
        }

        Ok(entries.into_iter())
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
