use vmi_core::{os::OsProcess, Architecture, Registers as _, Va, VmiDriver, VmiError, VmiSession};

use crate::{arch::ArchAdapter, WindowsOs, WindowsOsSessionExt as _};

pub struct LinkedListIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
    registers: &'a <Driver::Architecture as Architecture>::Registers,
    list_head: Va,
    offset: u64,
    entry: Option<Va>,
}

impl<'a, Driver> LinkedListIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new process iterator.
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
            entry: None,
        }
    }

    fn __first(&mut self) -> Result<Va, VmiError> {
        self.vmi.read_va(
            self.registers.address_context(self.list_head),
            self.registers.address_width(),
        )
    }

    fn __next(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.entry {
            Some(entry) => entry,
            None => {
                let flink = self.__first()?;
                self.entry = Some(flink);
                flink
            }
        };

        if entry == self.list_head {
            return Ok(None);
        }

        self.entry = Some(self.vmi.read_va(
            self.registers.address_context(entry),
            self.registers.address_width(),
        )?);

        Ok(Some(entry - self.offset))
    }
}

impl<Driver> Iterator for LinkedListIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.__next().transpose()
    }
}

////////////////////////////////////////////////////////////////////////////////

pub struct ProcessIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: LinkedListIterator<'a, Driver>,
}

impl<'a, Driver> ProcessIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new process iterator.
    pub fn new(
        session: VmiSession<'a, Driver, WindowsOs<Driver>>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        list_head: Va,
        offset: u64,
    ) -> Self {
        Self {
            inner: LinkedListIterator::new(session, registers, list_head, offset),
        }
    }
}

impl<Driver> Iterator for ProcessIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<OsProcess, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            result.and_then(|entry| {
                self.inner
                    .vmi
                    .os()
                    .process_object_to_process(self.inner.registers, entry.into())
            })
        })
    }
}
