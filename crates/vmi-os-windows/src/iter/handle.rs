use std::iter::FusedIterator;

use vmi_core::{Architecture, VmiError, driver::VmiRead};

use crate::{ArchAdapter, WindowsHandleTable, WindowsHandleTableEntry};

/// An iterator for traversing entries in a Windows handle table.
///
/// The functionality is similar to the Windows kernel's internal
/// `ExpSnapShotHandleTables()` function.
pub struct HandleTableEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state.
    handle_table: &'a WindowsHandleTable<'a, Driver>,

    /// Current handle value.
    current: u64,
}

impl<'a, Driver> HandleTableEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new handle table entry iterator.
    pub fn new(handle_table: &'a WindowsHandleTable<'a, Driver>) -> Self {
        Self {
            handle_table,
            current: 0,
        }
    }

    /// Walks to the next handle table entry.
    fn walk_next(
        &mut self,
    ) -> Result<Option<(u64, WindowsHandleTableEntry<'a, Driver>)>, VmiError> {
        const HANDLE_VALUE_INC: u64 = 4;

        while let Some(entry) = self.handle_table.lookup(self.current)? {
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
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<(u64, WindowsHandleTableEntry<'a, Driver>), VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> FusedIterator for HandleTableEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
