use std::iter::FusedIterator;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{ArchAdapter, LinuxOs};

/// An iterator for traversing list entries.
///
/// Iterate over entries in a linked list structure, specifically `LIST_ENTRY`.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

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
    offset_next: u64,

    /// Offset to the backward link pointer (`LIST_ENTRY.Blink`).
    offset_prev: u64,
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new list entry iterator.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, list_head: Va, offset: u64) -> Self {
        let __list_head = &vmi.underlying_os().offsets.list_head;
        let (offset_next, offset_prev) = (__list_head.next.offset(), __list_head.prev.offset());

        Self {
            vmi,
            current: None,
            list_head,
            offset,
            offset_next,
            offset_prev,
        }
    }

    fn __first(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va_native(self.list_head + self.offset_next)
    }

    fn __last(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va_native(self.list_head + self.offset_prev)
    }

    fn __next(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                let flink = self.__first()?;
                self.current = Some(flink);
                flink
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        self.current = Some(self.vmi.read_va_native(entry + self.offset_next)?);

        Ok(Some(entry - self.offset))
    }

    fn __next_back(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => {
                let blink = self.__last()?;
                self.current = Some(blink);
                blink
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        self.current = Some(self.vmi.read_va_native(entry + self.offset_prev)?);

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
        self.__next().transpose()
    }
}

impl<Driver> DoubleEndedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.__next_back().transpose()
    }
}

impl<Driver> FusedIterator for ListEntryIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
