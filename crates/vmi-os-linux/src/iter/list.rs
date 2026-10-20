use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, LinuxOs, offset};

/// Iterator over a `list_head` list.
///
/// The iterator starts at the entry after the list head and stops when it
/// comes back to the list head. For each entry, it yields the entry address
/// minus an offset. With the offset of the `list_head` field, that is the
/// containing structure, as the kernel's `list_entry` macro computes it.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the list head.
    list_head: Va,

    /// Offset of the `list_head` field in the containing structure.
    offset: u64,

    /// Current entry.
    current: Option<Va>,

    /// Whether the iterator read the list head.
    initialized: bool,
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new list entry iterator.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, list_head: Va, offset: u64) -> Self {
        Self {
            vmi,
            list_head,
            offset,
            current: None,
            initialized: false,
        }
    }

    /// Returns the next entry in the list.
    ///
    /// Corresponds to the `list_head.next` pointer.
    fn next_entry(&self, entry: Va) -> Result<Va, VmiError> {
        let LIST_HEAD = offset!(self.vmi, list_head);

        self.vmi.read_va_native(entry + LIST_HEAD.next.offset())
    }

    /// Returns the previous entry in the list.
    ///
    /// Corresponds to the `list_head.prev` pointer.
    fn previous_entry(&self, entry: Va) -> Result<Va, VmiError> {
        let LIST_HEAD = offset!(self.vmi, list_head);

        self.vmi.read_va_native(entry + LIST_HEAD.prev.offset())
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
                // An initialized iterator without a current entry is done,
                // either at the list head or after an error.
                if self.initialized {
                    return Ok(None);
                }

                self.initialized = true;

                match self.first_entry()? {
                    Some(first_entry) => first_entry,
                    None => return Ok(None),
                }
            }
        };

        if entry == self.list_head || entry.is_null() {
            self.current = None;
            return Ok(None);
        }

        match self.next_entry(entry) {
            Ok(next_entry) => self.current = Some(next_entry),
            Err(err) => {
                // End the iteration. Otherwise callers that continue on
                // errors read the same failing entry forever.
                self.current = None;
                return Err(err);
            }
        }

        Ok(Some(entry - self.offset))
    }

    /// Walks to the previous entry in the list.
    fn walk_next_back(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                if self.initialized {
                    return Ok(None);
                }

                self.initialized = true;

                match self.last_entry()? {
                    Some(last_entry) => last_entry,
                    None => return Ok(None),
                }
            }
        };

        if entry == self.list_head || entry.is_null() {
            self.current = None;
            return Ok(None);
        }

        match self.previous_entry(entry) {
            Ok(previous_entry) => self.current = Some(previous_entry),
            Err(err) => {
                self.current = None;
                return Err(err);
            }
        }

        Ok(Some(entry - self.offset))
    }
}

impl<Driver> Iterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> DoubleEndedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.walk_next_back().transpose()
    }
}

impl<Driver> FusedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
