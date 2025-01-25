use std::iter::FusedIterator;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{arch::ArchAdapter, WindowsOs};

/// An iterator for traversing list entries.
///
/// Iterate over entries in a linked list structure, specifically `LIST_ENTRY`.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
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
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new list entry iterator.
    pub fn new(
        vmi: VmiState<'a, Driver, WindowsOs<Driver>>,
        list_head: Va,
        offset: u64,
    ) -> Self {
        let LIST_ENTRY = &vmi.underlying_os().offsets()._LIST_ENTRY;
        let (offset_flink, offset_blink) = (LIST_ENTRY.Flink.offset, LIST_ENTRY.Blink.offset);

        Self {
            vmi,
            current: None,
            list_head,
            offset,
            offset_flink,
            offset_blink,
        }
    }

    fn __first(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va_native(self.list_head + self.offset_flink)
    }

    fn __last(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va_native(self.list_head + self.offset_blink)
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

        self.current = Some(self.vmi.read_va_native(entry + self.offset_flink)?);

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

        self.current = Some(self.vmi.read_va_native(entry + self.offset_blink)?);

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
