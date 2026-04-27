use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, WindowsKeyControlBlock, WindowsOs, offset};

/// An iterator over the key control blocks cached in a hive's
/// `_CMHIVE.KcbCacheTable`.
///
/// Walks every bucket in `_CMHIVE.KcbCacheTable` and, for each bucket,
/// follows the `_CM_KEY_HASH.NextHash` chain.
///
/// The yielded [`WindowsKeyControlBlock`] is recovered from the `_CM_KEY_HASH`
/// pointer by subtracting the offset of `_CM_KEY_CONTROL_BLOCK.KeyHash`.
///
/// Cached entries with the `Discarded` bit set are still yielded. The
/// caller decides whether to filter them, since the live KCBs are still
/// useful for diagnostic purposes.
pub struct KeyControlBlockIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_CM_KEY_HASH_TABLE_ENTRY` array.
    cache_va: Va,

    /// Number of buckets in the array.
    bucket_count: u32,

    /// Index of the next bucket to read.
    bucket_index: u32,

    /// Current `_CM_KEY_HASH*` in the active chain. Null means the
    /// iterator must advance to the following bucket.
    current: Va,
}

impl<'a, Driver> KeyControlBlockIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new KCB cache iterator over a resolved cache table.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, cache_va: Va, bucket_count: u32) -> Self {
        Self {
            vmi,
            cache_va,
            bucket_count,
            bucket_index: 0,
            current: Va(0),
        }
    }

    /// Creates an empty KCB cache iterator.
    pub fn empty(vmi: VmiState<'a, WindowsOs<Driver>>) -> Self {
        Self::new(vmi, Va(0), 0)
    }

    /// Advances the walk and returns the next KCB, if any.
    ///
    /// State advances before each failable read so that an error on one
    /// bucket or chain entry does not stall the iterator.
    fn walk_next(&mut self) -> Result<Option<WindowsKeyControlBlock<'a, Driver>>, VmiError> {
        let CM_KEY_HASH_TABLE_ENTRY = offset!(self.vmi, _CM_KEY_HASH_TABLE_ENTRY);
        let CM_KEY_HASH = offset!(self.vmi, _CM_KEY_HASH);
        let CM_KEY_CONTROL_BLOCK = offset!(self.vmi, _CM_KEY_CONTROL_BLOCK);

        loop {
            if self.current.is_null() {
                if self.bucket_index >= self.bucket_count {
                    return Ok(None);
                }

                let bucket_va = self.cache_va
                    + (self.bucket_index as u64) * CM_KEY_HASH_TABLE_ENTRY.len() as u64;
                self.bucket_index += 1;

                self.current = self
                    .vmi
                    .read_va_native(bucket_va + CM_KEY_HASH_TABLE_ENTRY.Entry.offset())?;

                continue;
            }

            let entry_va = self.current;
            self.current = Va(0);
            self.current = self
                .vmi
                .read_va_native(entry_va + CM_KEY_HASH.NextHash.offset())?;

            let kcb_va = entry_va - CM_KEY_CONTROL_BLOCK.KeyHash.offset();
            return Ok(Some(WindowsKeyControlBlock::new(self.vmi, kcb_va)));
        }
    }
}

impl<'a, Driver> Iterator for KeyControlBlockIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<WindowsKeyControlBlock<'a, Driver>, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> FusedIterator for KeyControlBlockIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
