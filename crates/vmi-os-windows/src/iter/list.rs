use vmi_core::{Architecture, Registers as _, Va, VmiDriver, VmiError, VmiSession};

use crate::{arch::ArchAdapter, WindowsOs};

/// An iterator for traversing list entries.
///
/// Iterate over entries in a linked list structure, specifically `LIST_ENTRY`.
pub struct ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
    registers: &'a <Driver::Architecture as Architecture>::Registers,

    /// Address of the list head.
    list_head: Va,

    /// Offset to the containing structure.
    ///
    /// The offset is subtracted from the entry address to get the containing
    /// structure, similar to the `CONTAINING_RECORD` macro in the Windows
    /// kernel.
    offset: u64,

    /// Current entry.
    current: Option<Va>,
}

impl<'a, Driver> ListEntryIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new list entry iterator.
    pub fn new(
        vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        list_head: Va,
        offset: u64,
    ) -> Self {
        Self {
            vmi,
            registers,
            list_head,
            offset,
            current: None,
        }
    }

    fn __first(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va(
            self.registers.address_context(self.list_head),
            self.registers.address_width(),
        )
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

        self.current = Some(self.vmi.read_va(
            self.registers.address_context(entry),
            self.registers.address_width(),
        )?);

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
