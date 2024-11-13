use vmi_core::{os::OsProcess, Architecture, Registers as _, Va, VmiDriver, VmiError, VmiSession};

use crate::{arch::ArchAdapter, offsets::OffsetsExt, WindowsOs, WindowsOsSessionExt as _};

pub struct TreeNodeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
    registers: &'a <Driver::Architecture as Architecture>::Registers,
    current: Option<Va>,

    offset_left: u64,
    offset_right: u64,
    offset_parent: u64,
}

impl<'a, Driver> TreeNodeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new process iterator.
    pub fn new(
        vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        root: Va,
    ) -> Result<Self, VmiError> {
        let offsets = vmi.underlying_os().offsets();

        let (mut current, offset_left, offset_right, offset_parent) = match &offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

                (
                    vmi.read_va(
                        registers.address_context(root + MMADDRESS_NODE.RightChild.offset),
                        registers.address_width(),
                    )?,
                    MMADDRESS_NODE.LeftChild.offset,
                    MMADDRESS_NODE.RightChild.offset,
                    MMADDRESS_NODE.Parent.offset,
                )
            }
            Some(OffsetsExt::V2(offsets)) => {
                let RTL_BALANCED_NODE = &offsets._RTL_BALANCED_NODE;

                (
                    root,
                    RTL_BALANCED_NODE.Left.offset,
                    RTL_BALANCED_NODE.Right.offset,
                    RTL_BALANCED_NODE.ParentValue.offset,
                )
            }
            None => panic!("OffsetsExt not set"),
        };

        loop {
            let left = vmi.read_va(
                registers.address_context(current + offset_left),
                registers.address_width(),
            )?;

            if left.is_null() {
                break;
            }

            current = left;
        }

        Ok(Self {
            vmi,
            registers,
            current: Some(current),
            offset_left,
            offset_right,
            offset_parent,
        })
    }

    fn left(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va(
            self.registers.address_context(node + self.offset_left),
            self.registers.address_width(),
        )
    }

    fn right(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va(
            self.registers.address_context(node + self.offset_right),
            self.registers.address_width(),
        )
    }

    fn parent(&self, node: Va) -> Result<Va, VmiError> {
        let result = self.vmi.read_va(
            self.registers.address_context(node + self.offset_parent),
            self.registers.address_width(),
        )?;

        //
        // We need to clear the Balance bits from the Parent pointer:
        //
        //   MMADDRESS_NODE:
        //     union {
        //         LONG_PTR Balance : 2;
        //         struct _MMADDRESS_NODE *Parent;
        //     }
        //
        //   RTL_BALANCED_NODE:
        //     union {
        //       UCHAR Red : 1;
        //       UCHAR Balance : 2;
        //       ULONG_PTR ParentValue;
        //     }
        //

        Ok(result & !0b11)
    }

    fn __next(&mut self) -> Result<Option<Va>, VmiError> {
        let result = self.current;

        let mut current = match self.current {
            Some(current) => current,
            None => return Ok(None),
        };

        let right = self.right(current)?;

        if !right.is_null() {
            current = right;

            loop {
                let left = self.left(current)?;

                if left.is_null() {
                    self.current = Some(current);
                    break;
                }

                current = left;
            }
        }
        else {
            loop {
                let parent = self.parent(current)?;

                if parent.is_null() || parent == current {
                    self.current = None;
                    break;
                }

                let left = self.left(parent)?;

                if left == current {
                    self.current = Some(parent);
                    break;
                }

                current = parent;
            }
        }

        Ok(result)
    }
}

impl<Driver> Iterator for TreeNodeIterator<'_, Driver>
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

pub struct ListEntryIterator<'a, Driver>
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

impl<'a, Driver> ListEntryIterator<'a, Driver>
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

////////////////////////////////////////////////////////////////////////////////

pub struct ProcessIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    inner: ListEntryIterator<'a, Driver>,
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
            inner: ListEntryIterator::new(session, registers, list_head, offset),
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
