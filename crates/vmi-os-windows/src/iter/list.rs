use std::iter::FusedIterator;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{ArchAdapter, WindowsOs};

/// An iterator for traversing list entries.
///
/// Iterate over entries in a linked list structure, specifically `LIST_ENTRY`.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// Current entry.
    current: Option<Va>,

    /// Address of the list head.
    list_head: Va,

    /// Offset to the containing structure.
    ///
    /// The offset is subtracted from the entry address to get the containing
    /// structure, similar to the `CONTAINING_RECORD` macro in the Windows
    /// kernel.
    offset: u64,

    /// Offset to the forward link pointer (`LIST_ENTRY.Flink`).
    offset_flink: u64,

    /// Offset to the backward link pointer (`LIST_ENTRY.Blink`).
    offset_blink: u64,

    /// Whether the iterator has been initialized.
    initialized: bool,
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new list entry iterator.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, list_head: Va, offset: u64) -> Self {
        let LIST_ENTRY = &vmi.underlying_os().offsets._LIST_ENTRY;
        let (offset_flink, offset_blink) = (LIST_ENTRY.Flink.offset(), LIST_ENTRY.Blink.offset());

        Self {
            vmi,
            current: None,
            list_head,
            offset,
            offset_flink,
            offset_blink,
            initialized: false,
        }
    }

    /// Creates an empty tree node iterator.
    pub fn empty(vmi: VmiState<'a, Driver, WindowsOs<Driver>>) -> Self {
        Self {
            vmi,
            current: None,
            list_head: Va(0),
            offset: 0,
            offset_flink: 0,
            offset_blink: 0,
            initialized: true,
        }
    }

    /// Returns the next entry in the list.
    ///
    /// Corresponds to the `LIST_ENTRY.Flink` pointer.
    fn next_entry(&self, entry: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(entry + self.offset_flink)
    }

    /// Returns the previous entry in the list.
    ///
    /// Corresponds to the `LIST_ENTRY.Blink` pointer.
    fn previous_entry(&self, entry: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(entry + self.offset_blink)
    }

    /// Returns the first entry in the list.
    ///
    /// Returns `None` if the `list_head` is `NULL`.
    fn first_entry(&self) -> Result<Option<Va>, VmiError> {
        if self.list_head.is_null() {
            return Ok(None);
        }

        Ok(Some(self.next_entry(self.list_head)?))
    }

    /// Returns the last entry in the list.
    ///
    /// Returns `None` if the `list_head` is `NULL`.
    fn last_entry(&self) -> Result<Option<Va>, VmiError> {
        if self.list_head.is_null() {
            return Ok(None);
        }

        Ok(Some(self.previous_entry(self.list_head)?))
    }

    /// Walks to the next entry in the list.
    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                // If `self.current` is `None`, we need to initialize the iterator.
                //
                // However, if the iterator has already been initialized, we should
                // return `None` to prevent infinite iteration.
                if self.initialized {
                    return Ok(None);
                }

                let first = match self.first_entry()? {
                    Some(first) => first,
                    None => return Ok(None),
                };

                self.current = Some(first);
                self.initialized = true;
                first
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        self.current = Some(self.next_entry(entry)?);

        Ok(Some(entry - self.offset))
    }

    /// Walks to the previous entry in the list.
    fn walk_next_back(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                // If `self.current` is `None`, we need to initialize the iterator.
                //
                // However, if the iterator has already been initialized, we should
                // return `None` to prevent infinite iteration.
                if self.initialized {
                    return Ok(None);
                }

                let last = match self.last_entry()? {
                    Some(last) => last,
                    None => return Ok(None),
                };

                self.current = Some(last);
                self.initialized = true;
                last
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        self.current = Some(self.previous_entry(entry)?);

        Ok(Some(entry - self.offset))
    }
}

impl<Driver> Iterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> DoubleEndedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.walk_next_back().transpose()
    }
}

impl<Driver> FusedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
