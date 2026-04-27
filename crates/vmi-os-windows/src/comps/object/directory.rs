use vmi_core::{Registers as _, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{FromWindowsObject, WindowsObject, WindowsObjectTypeKind};
use crate::{ArchAdapter, DirectoryObjectIterator, WindowsOs, offset};

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
        Ok(DirectoryObjectIterator::new(self.vmi, self.va))
    }

    /// Resolves a relative path to a descendant object.
    ///
    /// Splits `path` on `\\` and descends one component at a time. Empty
    /// segments are ignored. Name comparison is ASCII-case-insensitive.
    /// Each intermediate component must resolve to a `Directory` object.
    ///
    /// Returns `Ok(None)` if a component does not exist or an intermediate
    /// is some other object type. The final component may be any type. An
    /// empty path returns this directory.
    ///
    /// Does not follow `SymbolicLink` objects.
    pub fn lookup(
        &self,
        path: impl AsRef<str>,
    ) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let path = path.as_ref();
        let mut components = path.split('\\').filter(|component| !component.is_empty());

        let first = match components.next() {
            Some(first) => first,
            None => return Ok(Some(WindowsObject::new(self.vmi, self.va))),
        };

        let mut directory = WindowsDirectoryObject::new(self.vmi, self.va);
        let mut next = first;
        for component in components {
            let object = match directory.child(next)? {
                Some(object) => object,
                None => return Ok(None),
            };

            directory = match WindowsDirectoryObject::from_object(object)? {
                Some(dir) => dir,
                None => return Ok(None),
            };

            next = component;
        }

        directory.child(next)
    }

    /// Returns the direct entry with the given name, if any.
    ///
    /// `name` is treated as a single component. It is not split on `\\`,
    /// so `child("Device\\HarddiskVolume4")` will never match a real entry -
    /// use [`lookup`] for path traversal.
    ///
    /// Walks every hash bucket and matches names with ASCII-case-insensitive
    /// comparison.
    ///
    /// Per-bucket read errors do not abort the search. A paged-out bucket
    /// head or chain-link page would otherwise mask matches in other buckets.
    /// Errors are skipped.
    ///
    /// [`lookup`]: Self::lookup
    pub fn child(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        const NUMBER_HASH_BUCKETS: u64 = 37;

        let OBJECT_DIRECTORY = offset!(self.vmi, _OBJECT_DIRECTORY);

        let name = name.as_ref();
        let address_width = self.vmi.registers().address_width() as u64;

        for index in 0..NUMBER_HASH_BUCKETS {
            let bucket = self.va + OBJECT_DIRECTORY.HashBuckets.offset() + index * address_width;

            match self.lookup_in_bucket(bucket, name) {
                Ok(Some(object)) => return Ok(Some(object)),
                Ok(None) => {}
                Err(err) => {
                    tracing::trace!(%err, index, "skipping directory bucket after read error");
                }
            }
        }

        Ok(None)
    }

    /// Walks one hash bucket linked list looking for `name`.
    fn lookup_in_bucket(
        &self,
        bucket: Va,
        name: &str,
    ) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let OBJECT_DIRECTORY_ENTRY = offset!(self.vmi, _OBJECT_DIRECTORY_ENTRY);

        let mut entry = self.vmi.read_va_native(bucket)?;
        while !entry.is_null() {
            let object = self
                .vmi
                .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.Object.offset())?;

            let object = WindowsObject::new(self.vmi, object);

            match object.name() {
                Ok(Some(entry_name)) => {
                    if entry_name.eq_ignore_ascii_case(name) {
                        return Ok(Some(object));
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::trace!(%err, "skipping directory entry with unreadable name");
                }
            }

            entry = self
                .vmi
                .read_va_native(entry + OBJECT_DIRECTORY_ENTRY.ChainLink.offset())?;
        }

        Ok(None)
    }
}
