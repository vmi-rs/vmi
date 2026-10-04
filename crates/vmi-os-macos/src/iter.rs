//! Iterators over XNU linked lists.

use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, MacOs, MacOsError, MacOsExt as _, offset};

/// Upper bound on the number of elements yielded from one list.
///
/// A list that is longer than this is treated as corrupted.
pub(crate) const MAX_LIST_LENGTH: usize = 1 << 16;

/// An iterator over a BSD `LIST` from `<sys/queue.h>`.
///
/// Each `le_next` link points to the start of the next element, and the last
/// element links to null. The iterator yields the address of each element.
pub struct ListIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the next element, or null at the end of the list.
    current: Va,

    /// Offset of the `le_next` link within an element.
    link_offset: u64,

    /// Number of elements that may still be yielded.
    remaining: usize,
}

impl<'a, Driver> ListIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates an iterator starting at the element `first`.
    ///
    /// `link_offset` is the offset of the `le_next` link within an element.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, first: Va, link_offset: u64) -> Self {
        Self {
            vmi,
            current: first,
            link_offset,
            remaining: MAX_LIST_LENGTH,
        }
    }
}

impl<Driver> Iterator for ListIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }

        if self.remaining == 0 {
            self.current = Va(0);
            return Some(Err(MacOsError::CorruptedStruct("LIST too long").into()));
        }

        self.remaining -= 1;

        let entry = self.current;
        match self.vmi.os().read_pointer(entry + self.link_offset) {
            Ok(next) => self.current = next,
            Err(err) => {
                self.current = Va(0);
                return Some(Err(err));
            }
        }

        Some(Ok(entry))
    }
}

impl<Driver> FusedIterator for ListIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}

/// An iterator over a Mach queue from `<kern/queue.h>`.
///
/// The queue head is a `queue_head_t` and each element embeds a
/// `queue_chain_t`. The `next` links of the head and of each chain point to
/// the start of the next element, and the last element links back to the
/// head. The iterator yields the address of each element.
pub struct QueueIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the queue head.
    head: Va,

    /// Offset of the `queue_chain_t` within an element.
    chain_offset: u64,

    /// Address of the next element, `None` before the head is read.
    current: Option<Va>,

    /// Number of elements that may still be yielded.
    remaining: usize,

    /// Whether the iteration has ended.
    done: bool,
}

impl<'a, Driver> QueueIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates an iterator over the queue with the head at `head`.
    ///
    /// `chain_offset` is the offset of the `queue_chain_t` within an element.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, head: Va, chain_offset: u64) -> Self {
        Self {
            vmi,
            head,
            chain_offset,
            current: None,
            remaining: MAX_LIST_LENGTH,
            done: false,
        }
    }

    /// Creates an iterator that yields nothing.
    pub fn empty(vmi: VmiState<'a, MacOs<Driver>>) -> Self {
        Self {
            vmi,
            head: Va(0),
            chain_offset: 0,
            current: None,
            remaining: 0,
            done: true,
        }
    }

    /// Reads the `next` link of the queue entry at `entry`.
    fn next_link(&self, entry: Va) -> Result<Va, VmiError> {
        let queue_entry = offset!(self.vmi, queue_entry);

        self.vmi
            .os()
            .read_pointer(entry + queue_entry.next.offset())
    }

    /// Returns the next element, or `None` at the end of the queue.
    fn advance(&mut self) -> Result<Option<Va>, VmiError> {
        let entry = match self.current {
            Some(entry) => entry,
            None => self.next_link(self.head)?,
        };

        if entry == self.head || entry.is_null() {
            return Ok(None);
        }

        if self.remaining == 0 {
            return Err(MacOsError::CorruptedStruct("queue too long").into());
        }

        self.remaining -= 1;
        self.current = Some(self.next_link(entry + self.chain_offset)?);
        Ok(Some(entry))
    }
}

impl<Driver> Iterator for QueueIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.advance() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }
}

impl<Driver> FusedIterator for QueueIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}

/// An iterator over the entries of a `struct _vm_map`.
///
/// The map header acts as the sentinel of a circular list linked through
/// `vm_map_entry.vme_next`, in ascending address order. The iterator yields
/// the address of each `struct vm_map_entry`, and stops after the number of
/// entries that the header records.
pub struct MapEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the map header.
    header: Va,

    /// Address of the next entry.
    current: Va,

    /// Number of entries that may still be yielded.
    remaining: usize,
}

impl<'a, Driver> MapEntryIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates an iterator over the entries of the map at `map`.
    ///
    /// # Implementation Details
    ///
    /// Starts at `_vm_map.hdr.first` and yields at most
    /// `_vm_map.hdr.nentries` entries.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, map: Va) -> Result<Self, VmiError> {
        let vm_map = offset!(vmi, _vm_map);
        let vm_map_header = offset!(vmi, vm_map_copy);

        let header = map + vm_map.hdr.offset();
        let first = vmi
            .os()
            .read_pointer(header + vm_map_header.first.offset())?;
        let count = vmi.read_u32(header + vm_map_header.nentries.offset())? as i32;

        if !(0..=MAX_LIST_LENGTH as i32).contains(&count) {
            return Err(MacOsError::CorruptedStruct("vm_map_header.nentries").into());
        }

        Ok(Self {
            vmi,
            header,
            current: first,
            remaining: count as usize,
        })
    }

    /// Creates an iterator that yields nothing.
    pub fn empty(vmi: VmiState<'a, MacOs<Driver>>) -> Self {
        Self {
            vmi,
            header: Va(0),
            current: Va(0),
            remaining: 0,
        }
    }
}

impl<Driver> Iterator for MapEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        let vm_map_entry = offset!(self.vmi, vm_map_entry);

        if self.remaining == 0 || self.current.is_null() || self.current == self.header {
            return None;
        }

        self.remaining -= 1;

        let entry = self.current;
        match self
            .vmi
            .os()
            .read_pointer(entry + vm_map_entry.vme_next.offset())
        {
            Ok(next) => self.current = next,
            Err(err) => {
                self.remaining = 0;
                return Some(Err(err));
            }
        }

        Some(Ok(entry))
    }
}

impl<Driver> FusedIterator for MapEntryIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
