use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, WindowsObject, WindowsOs};

/// An iterator for traversing objects stored in a Windows
/// `_OBJECT_DIRECTORY`.
///
/// Walks every hash bucket in the directory and, for each bucket, follows
/// the `_OBJECT_DIRECTORY_ENTRY.ChainLink` chain. Entries are yielded one
/// at a time. Buckets and chains are read on demand as the iterator
/// advances.
pub struct DirectoryObjectIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Virtual address of the `_OBJECT_DIRECTORY`.
    directory_va: Va,

    /// Offset of `_OBJECT_DIRECTORY.HashBuckets`.
    hash_buckets_offset: u64,

    /// Offset of `_OBJECT_DIRECTORY_ENTRY.ChainLink`.
    chain_link_offset: u64,

    /// Offset of `_OBJECT_DIRECTORY_ENTRY.Object`.
    object_offset: u64,

    /// Index of the next hash bucket to read.
    bucket: u64,

    /// Next entry in the current bucket's chain, or `None` if the
    /// iterator needs to advance to the following bucket.
    entry: Option<Va>,
}

impl<'a, Driver> DirectoryObjectIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new directory object iterator from pre-read layout
    /// offsets.
    pub fn new(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        directory_va: Va,
        hash_buckets_offset: u64,
        chain_link_offset: u64,
        object_offset: u64,
    ) -> Self {
        Self {
            vmi,
            directory_va,
            hash_buckets_offset,
            chain_link_offset,
            object_offset,
            bucket: 0,
            entry: None,
        }
    }

    /// Walks to the next directory entry.
    fn walk_next(&mut self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        const BUCKET_COUNT: u64 = 37;
        const SIZEOF_POINTER: u64 = 8;

        loop {
            let entry = match self.entry.take() {
                Some(entry) => entry,
                None => {
                    if self.bucket >= BUCKET_COUNT {
                        return Ok(None);
                    }

                    let hash_bucket = self.vmi.read_va_native(
                        self.directory_va + self.hash_buckets_offset + self.bucket * SIZEOF_POINTER,
                    )?;
                    self.bucket += 1;

                    if hash_bucket.is_null() {
                        continue;
                    }

                    hash_bucket
                }
            };

            let object = self.vmi.read_va_native(entry + self.object_offset)?;
            let next = self.vmi.read_va_native(entry + self.chain_link_offset)?;

            self.entry = if next.is_null() { None } else { Some(next) };

            return Ok(Some(WindowsObject::new(self.vmi, object)));
        }
    }
}

impl<'a, Driver> Iterator for DirectoryObjectIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<WindowsObject<'a, Driver>, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> FusedIterator for DirectoryObjectIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
