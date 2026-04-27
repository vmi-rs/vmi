use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{
    ArchAdapter, WindowsError, WindowsHive, WindowsHiveCellIndex, WindowsKeyValue, WindowsOs,
    comps::hive::HCELL_INDEX_SIZE,
};

/// An iterator over the values of a `_CM_KEY_NODE`.
///
/// Walks the `_CM_KEY_VALUE_LIST` - a flat array of `HCELL_INDEX`es - one
/// entry at a time and yields each resolved `_CM_KEY_VALUE` as a
/// [`WindowsKeyValue`].
pub struct KeyValueIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the owning `_CMHIVE`.
    hive_va: Va,

    /// Address of the first HCELL_INDEX entry in the `_CM_KEY_VALUE_LIST`.
    /// Unused when `count == 0`.
    list_va: Va,

    /// Total number of entries in the list.
    count: u32,

    /// Position of the next entry to read.
    position: u32,
}

impl<'a, Driver> KeyValueIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new value iterator over a resolved `_CM_KEY_VALUE_LIST`.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, hive_va: Va, list_va: Va, count: u32) -> Self {
        Self {
            vmi,
            hive_va,
            list_va,
            count,
            position: 0,
        }
    }

    /// Creates an empty value iterator.
    pub fn empty(vmi: VmiState<'a, WindowsOs<Driver>>, hive_va: Va) -> Self {
        Self {
            vmi,
            hive_va,
            list_va: Va(0),
            count: 0,
            position: 0,
        }
    }

    /// Advances the walk and returns the next value, if any.
    ///
    /// `position` advances before any read, so an error on one entry does
    /// not stall the iterator on that same entry forever.
    fn walk_next(&mut self) -> Result<Option<WindowsKeyValue<'a, Driver>>, VmiError> {
        if self.position >= self.count {
            return Ok(None);
        }

        let entry_va = self.list_va + (self.position as u64) * HCELL_INDEX_SIZE;
        self.position += 1;

        let hcell = self.vmi.read_u32(entry_va)?;

        // The kernel guarantees every entry in `_CM_KEY_VALUE_LIST.List[]` is
        // a valid `HCELL_INDEX`.
        let hive = WindowsHive::new(self.vmi, self.hive_va);
        match hive.cell(WindowsHiveCellIndex::new(hcell))? {
            Some(va) => Ok(Some(WindowsKeyValue::new(self.vmi, self.hive_va, va))),
            None => Err(WindowsError::CorruptedStruct("CM_KEY_VALUE_LIST.List[]").into()),
        }
    }
}

impl<'a, Driver> Iterator for KeyValueIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<WindowsKeyValue<'a, Driver>, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.count - self.position) as usize;
        (n, Some(n))
    }
}

impl<Driver> FusedIterator for KeyValueIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}

impl<Driver> ExactSizeIterator for KeyValueIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
