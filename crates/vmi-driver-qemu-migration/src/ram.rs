use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    rc::Rc,
};

use memmap2::Mmap;
use zerocopy::IntoBytes as _;

use crate::{Error, cursor::Cursor};

/// Flag of a RAM record that holds a page of zeros (`migration/ram.h`).
const RAM_SAVE_FLAG_ZERO: u64 = 0x002;

/// Flag of the RAM record that lists the RAM blocks (`migration/ram.h`).
const RAM_SAVE_FLAG_MEM_SIZE: u64 = 0x004;

/// Flag of a RAM record that holds the data of a page (`migration/ram.h`).
const RAM_SAVE_FLAG_PAGE: u64 = 0x008;

/// Flag of the RAM record that ends a part of the RAM section
/// (`migration/ram.h`).
const RAM_SAVE_FLAG_EOS: u64 = 0x010;

/// Flag of a page record that belongs to the block of the previous record and
/// does not name a block (`migration/ram.h`).
const RAM_SAVE_FLAG_CONTINUE: u64 = 0x020;

/// Marks a page that reads as zero in [`RamBlock::pages`].
///
/// Offset 0 of the stream holds the magic number, never page data.
const ZERO_PAGE: u64 = 0;

/// A range of guest physical memory backed by a RAM block of the stream.
///
/// The stream addresses RAM by block and offset, not by guest physical
/// address. The machine type decides where each block appears in guest
/// physical memory. [`ArchAdapter::ram_ranges`](crate::ArchAdapter::ram_ranges)
/// returns these ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    /// Name of the RAM block, such as `pc.ram`.
    pub block: &'static str,

    /// Offset of the range within the RAM block.
    pub offset: u64,

    /// Guest physical address of the first byte of the range.
    pub address: u64,

    /// Length of the range in bytes.
    pub length: u64,
}

/// The pages of one RAM block, as the stream holds them.
pub(crate) struct RamBlock {
    /// Name of the block, such as `pc.ram`.
    pub name: String,

    /// Length of the block in bytes.
    pub length: u64,

    /// File offset of the data of each page, or [`ZERO_PAGE`].
    ///
    /// The last record of a page decides its content. A page without a
    /// record reads as zero, as it does in a VM that loads the stream.
    pages: Vec<u64>,
}

/// The RAM blocks of a migration stream and the location of their pages.
pub(crate) struct Ram {
    /// Target page size of the stream.
    page_size: u64,

    /// Blocks in stream order.
    blocks: Vec<RamBlock>,

    /// Indexes into `blocks`, by block name.
    names: HashMap<String, usize>,

    /// Index of the block of the last record that named its block.
    current: Option<usize>,
}

impl Ram {
    /// Creates an empty set of RAM blocks for a stream with `page_size`
    /// bytes per page.
    pub fn new(page_size: u64) -> Self {
        Self {
            page_size,
            blocks: Vec::new(),
            names: HashMap::new(),
            current: None,
        }
    }

    /// Returns the blocks in stream order.
    pub fn blocks(&self) -> &[RamBlock] {
        &self.blocks
    }

    /// Reads the RAM records of one part of the RAM section, up to and
    /// including the record that ends it.
    ///
    /// Each record starts with a big-endian 64-bit integer that holds the
    /// offset of a page within its block and the flags in the bits below
    /// the page size (`ram_load_precopy` in `migration/ram.c`).
    pub fn read_section(&mut self, cursor: &mut Cursor) -> Result<(), Error> {
        loop {
            let offset = cursor.offset();
            let header = cursor.be64()?;
            let flags = header & (self.page_size - 1);
            let address = header & !(self.page_size - 1);

            match flags & !RAM_SAVE_FLAG_CONTINUE {
                RAM_SAVE_FLAG_EOS => return Ok(()),
                RAM_SAVE_FLAG_MEM_SIZE => self.read_blocks(cursor, address)?,
                RAM_SAVE_FLAG_ZERO => {
                    let block = self.read_block(cursor, flags, offset)?;
                    let value = cursor.u8()?;
                    if value != 0 {
                        return Err(Error::InvalidZeroPage {
                            value,
                            offset: offset as u64,
                        });
                    }

                    self.set_page(block, address, ZERO_PAGE, offset)?;
                }
                RAM_SAVE_FLAG_PAGE => {
                    let block = self.read_block(cursor, flags, offset)?;
                    let data = cursor.offset();
                    cursor.bytes(self.page_size as usize)?;
                    self.set_page(block, address, data as u64, offset)?;
                }
                _ => {
                    return Err(Error::UnsupportedRamFlags {
                        flags,
                        offset: offset as u64,
                    });
                }
            }
        }
    }

    /// Reads the list of RAM blocks, which the record with the
    /// `RAM_SAVE_FLAG_MEM_SIZE` flag holds.
    ///
    /// `total` is the sum of the block lengths. Each entry is the block name
    /// with a one-byte length and the block length as a big-endian 64-bit
    /// integer (`ram_save_setup` in `migration/ram.c`).
    fn read_blocks(&mut self, cursor: &mut Cursor, total: u64) -> Result<(), Error> {
        let mut remaining = total;
        while remaining > 0 {
            let offset = cursor.offset();
            let name = cursor.name()?;
            let length = cursor.be64()?;

            remaining = match remaining.checked_sub(length) {
                Some(remaining) if !self.names.contains_key(name) => remaining,
                _ => {
                    return Err(Error::InvalidRamBlockList {
                        offset: offset as u64,
                    });
                }
            };

            self.names.insert(name.into(), self.blocks.len());
            self.blocks.push(RamBlock {
                name: name.into(),
                length,
                pages: vec![ZERO_PAGE; length.div_ceil(self.page_size) as usize],
            });
        }

        Ok(())
    }

    /// Reads the block of a page record and returns its index.
    ///
    /// A record with the `RAM_SAVE_FLAG_CONTINUE` flag belongs to the block
    /// of the last record that named its block. Other records name their
    /// block after the header (`save_page_header` in `migration/ram.c`).
    fn read_block(
        &mut self,
        cursor: &mut Cursor,
        flags: u64,
        offset: usize,
    ) -> Result<usize, Error> {
        if flags & RAM_SAVE_FLAG_CONTINUE != 0 {
            return match self.current {
                Some(current) => Ok(current),
                None => Err(Error::NoCurrentRamBlock {
                    offset: offset as u64,
                }),
            };
        }

        let name = cursor.name()?;
        match self.names.get(name) {
            Some(block) => {
                self.current = Some(*block);
                Ok(*block)
            }
            None => Err(Error::UnknownRamBlock {
                name: name.into(),
                offset: offset as u64,
            }),
        }
    }

    /// Records the content of one page of a block.
    fn set_page(
        &mut self,
        block: usize,
        address: u64,
        content: u64,
        offset: usize,
    ) -> Result<(), Error> {
        let block = &mut self.blocks[block];
        match block.pages.get_mut((address / self.page_size) as usize) {
            Some(page) => {
                *page = content;
                Ok(())
            }
            None => Err(Error::RamAddressOutOfBounds {
                block: block.name.clone(),
                address,
                offset: offset as u64,
            }),
        }
    }
}

/// A range of guest physical memory with the index of its RAM block.
#[derive(Debug, Clone, Copy)]
struct MappedRange {
    /// Guest physical address of the first byte of the range.
    address: u64,

    /// End of the range, exclusive.
    end: u64,

    /// Index of the RAM block.
    block: usize,

    /// Offset of the range within the RAM block.
    offset: u64,
}

/// Alignment of the pages that the driver returns.
///
/// The arch crates read page tables in place as slices of 64-bit entries,
/// such as `vmi-arch-amd64` with `ref_from_bytes`, which needs this
/// alignment. In the stream, the data of a page follows the header of its
/// record and sometimes a block name, so it is aligned only by chance.
pub(crate) const PAGE_ALIGN: usize = align_of::<u64>();

/// A range of the memory-mapped stream that holds one page.
///
/// Keeps the mapping alive, so the range can back a page without a copy.
pub(crate) struct PageData {
    /// Shared mapping of the stream.
    mmap: Rc<Mmap>,

    /// Start of the range within the stream.
    start: usize,

    /// End of the range within the stream.
    end: usize,
}

impl Deref for PageData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap[self.start..self.end]
    }
}

/// A copy of a page with the alignment of [`PAGE_ALIGN`].
pub(crate) struct PageBuffer(Box<[u64]>);

impl PageBuffer {
    /// Creates a page of `size` zero bytes, rounded down to a multiple of
    /// [`PAGE_ALIGN`].
    fn zeroed(size: usize) -> Self {
        Self(vec![0; size / PAGE_ALIGN].into_boxed_slice())
    }
}

impl Deref for PageBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

impl DerefMut for PageBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_bytes()
    }
}

/// A page of guest physical memory.
pub(crate) enum Page {
    /// The page reads as zero.
    Zero,

    /// One page of the stream holds the page, at an aligned offset.
    Mapped(PageData),

    /// The page was copied out of the stream, because its data is not
    /// aligned or spans several pages of the stream.
    Copied(PageBuffer),
}

/// Guest physical memory, mapped onto the RAM blocks of the stream.
pub(crate) struct Memory {
    /// Shared mapping of the stream.
    mmap: Rc<Mmap>,

    /// Target page size of the stream.
    page_size: u64,

    /// RAM blocks in stream order.
    blocks: Vec<RamBlock>,

    /// Ranges sorted by guest physical address, without overlaps.
    ranges: Vec<MappedRange>,
}

impl Memory {
    /// Maps the RAM blocks of `ram` into guest physical memory.
    ///
    /// Each range must name a block of the stream, lie within it and be
    /// aligned to the page size of the stream. Ranges must not overlap.
    /// Empty ranges are ignored.
    pub fn new(mmap: Rc<Mmap>, ram: Ram, ranges: &[RamRange]) -> Result<Self, Error> {
        let mut mapped = Vec::with_capacity(ranges.len());
        for range in ranges.iter().filter(|range| range.length != 0) {
            let invalid = || Error::InvalidRamRange {
                block: range.block.into(),
                address: range.address,
            };

            let block = match ram.names.get(range.block) {
                Some(block) => *block,
                None => {
                    return Err(Error::MissingRamBlock {
                        block: range.block.into(),
                    });
                }
            };

            let aligned = (range.offset | range.address | range.length) % ram.page_size == 0;
            let within = range
                .offset
                .checked_add(range.length)
                .is_some_and(|end| end <= ram.blocks[block].length);
            let end = range.address.checked_add(range.length);

            match end {
                Some(end) if aligned && within => mapped.push(MappedRange {
                    address: range.address,
                    end,
                    block,
                    offset: range.offset,
                }),
                _ => return Err(invalid()),
            }
        }

        mapped.sort_by_key(|range| range.address);
        for pair in mapped.windows(2) {
            if pair[1].address < pair[0].end {
                return Err(Error::InvalidRamRange {
                    block: ram.blocks[pair[1].block].name.clone(),
                    address: pair[1].address,
                });
            }
        }

        Ok(Self {
            mmap,
            page_size: ram.page_size,
            blocks: ram.blocks,
            ranges: mapped,
        })
    }

    /// Returns the end of the highest range, or 0 without ranges.
    pub fn end(&self) -> u64 {
        match self.ranges.last() {
            Some(range) => range.end,
            None => 0,
        }
    }

    /// Returns the file offset of the data of the stream page at a guest
    /// physical address, [`ZERO_PAGE`], or `None` when no range covers the
    /// address.
    fn stream_page(&self, address: u64) -> Option<u64> {
        // The first range that ends after `address`.
        let index = self.ranges.partition_point(|range| range.end <= address);
        let range = self.ranges.get(index)?;
        if address < range.address {
            return None;
        }

        let offset = range.offset + (address - range.address);
        Some(self.blocks[range.block].pages[(offset / self.page_size) as usize])
    }

    /// Reads a page of guest physical memory.
    ///
    /// `address` and `size` must be multiples of the page size of the
    /// stream. Parts of the page that no range covers read as zero. Returns
    /// `None` when no range covers any part of the page.
    pub fn read(&self, address: u64, size: u64) -> Option<Page> {
        let stream_page =
            |index: u64| self.stream_page(address.checked_add(index * self.page_size)?);

        if size == self.page_size {
            let start = match stream_page(0)? {
                ZERO_PAGE => return Some(Page::Zero),
                start => start as usize,
            };

            let end = start + size as usize;
            if start % PAGE_ALIGN == 0 {
                return Some(Page::Mapped(PageData {
                    mmap: self.mmap.clone(),
                    start,
                    end,
                }));
            }

            let mut buffer = PageBuffer::zeroed(size as usize);
            buffer.copy_from_slice(&self.mmap[start..end]);
            return Some(Page::Copied(buffer));
        }

        let count = size / self.page_size;
        let mut covered = false;
        let mut data = false;
        for index in 0..count {
            match stream_page(index) {
                Some(ZERO_PAGE) => covered = true,
                Some(_) => data = true,
                None => (),
            }
        }

        if !covered && !data {
            return None;
        }

        if !data {
            return Some(Page::Zero);
        }

        let mut buffer = PageBuffer::zeroed(size as usize);
        for (index, chunk) in buffer.chunks_exact_mut(self.page_size as usize).enumerate() {
            if let Some(start) = stream_page(index as u64)
                && start != ZERO_PAGE
            {
                let start = start as usize;
                chunk.copy_from_slice(&self.mmap[start..start + chunk.len()]);
            }
        }

        Some(Page::Copied(buffer))
    }
}
