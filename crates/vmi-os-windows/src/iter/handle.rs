use std::iter::FusedIterator;

use vmi_core::{VmiError, VmiState, driver::VmiRead};

use crate::{
    ArchAdapter, WindowsHandleTableEntry, WindowsOs, comps::handle_table::lookup_handle_entry,
};

/// An iterator for traversing entries in a Windows handle table.
///
/// The functionality is similar to the Windows kernel's internal
/// `ExpSnapShotHandleTables()` function.
pub struct HandleTableEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Snapshot of `_HANDLE_TABLE.TableCode`.
    table_code: u64,

    /// Snapshot of `_HANDLE_TABLE.NextHandleNeedingPool`.
    next_handle_needing_pool: u64,

    /// Current handle value.
    current: u64,
}

impl<'a, Driver> HandleTableEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new handle table entry iterator from pre-read handle-table
    /// state.
    pub fn new(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        table_code: u64,
        next_handle_needing_pool: u64,
    ) -> Self {
        Self {
            vmi,
            table_code,
            next_handle_needing_pool,
            current: 0,
        }
    }

    /// Walks to the next handle table entry.
    fn walk_next(
        &mut self,
    ) -> Result<Option<(u64, WindowsHandleTableEntry<'a, Driver>)>, VmiError> {
        const HANDLE_VALUE_INC: u64 = 4;

        while let Some(entry) = lookup_handle_entry(
            self.vmi,
            self.table_code,
            self.next_handle_needing_pool,
            self.current,
        )? {
            let handle = self.current;
            self.current += HANDLE_VALUE_INC;

            if entry.object()?.is_some() {
                return Ok(Some((handle, entry)));
            }
        }

        Ok(None)
    }
}

impl<'a, Driver> Iterator for HandleTableEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<(u64, WindowsHandleTableEntry<'a, Driver>), VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> FusedIterator for HandleTableEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
