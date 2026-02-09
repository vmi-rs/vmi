//! A MapleTree implementation based on the Linux kernel's data structure.
//!
//! The Maple Tree is a data structure used in the Linux kernel for efficiently storing
//! and searching ranges of values. It's particularly used for managing virtual memory
//! areas (VMAs) in the memory management subsystem.
//!
//! # References
//!
//! - [Linux Kernel Source - maple_tree.c](https://elixir.bootlin.com/linux/v6.10.5/source/lib/maple_tree.c)
//! - [Linux Kernel Source - maple_tree.h](https://elixir.bootlin.com/linux/v6.10.5/source/include/linux/maple_tree.h)
//! - [Process Address Space Documentation](https://students.mimuw.edu.pl/ZSO/Wyklady/04_processes2/ProcessAddressSpace.pdf)
//! - [Maple Tree: Storing Ranges](https://blogs.oracle.com/linux/post/maple-tree-storing-ranges)
//! - [Kernel Documentation - Maple Tree](https://docs.kernel.org/core-api/maple_tree.html)

#![allow(dead_code)]
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{LinuxOs, arch::ArchAdapter};

/// Represents different node types in a Maple Tree.
#[derive(Debug)]
enum MapleType {
    /// Dense nodes contain directly addressable slots.
    Dense,

    /// Leaf nodes.
    Leaf64,

    /// Range nodes.
    Range64,

    /// Allocation range nodes.
    Arange64,
}

/// Create an internal entry.
/// @v: Value to turn into an internal entry.
///
/// Internal entries are used for a number of purposes.  Entries 0-255 are
/// used for sibling entries (only 0-62 are used by the current code).  256
/// is used for the retry entry.  257 is used for the reserved / zero entry.
/// Negative internal entries are used to represent errnos.  Node pointers
/// are also tagged as internal entries in some situations.
///
/// Context: Any context.
/// Return: An XArray internal entry corresponding to this value.
const fn xa_mk_internal(v: u64) -> Va {
    Va::new((v << 2) | 2)
}

/// Extract the value from an internal entry.
/// @entry: XArray entry.
///
/// Context: Any context.
/// Return: The value which was stored in the internal entry.
const fn xa_to_internal(entry: Va) -> u64 {
    entry.0 >> 2
}

/// Is the entry an internal entry?
/// @entry: XArray entry.
///
/// Context: Any context.
/// Return: %true if the entry is an internal entry.
const fn xa_is_internal(entry: Va) -> bool {
    (entry.0 & 3) == 2
}

/// Is the entry a zero entry?
/// @entry: Entry retrieved from the XArray
///
/// The normal API will return NULL as the contents of a slot containing
/// a zero entry.  You can only see zero entries by using the advanced API.
///
/// Return: %true if the entry is a zero entry.
const fn xa_is_zero(entry: Va) -> bool {
    const XA_ZERO_ENTRY: Va = xa_mk_internal(257);
    entry.0 == XA_ZERO_ENTRY.0
}

/// Get value stored in an XArray entry.
/// @entry: XArray entry.
///
/// Context: Any context.
/// Return: The value stored in the XArray entry.
const fn xa_to_value(entry: Va) -> u64 {
    entry.0 >> 1
}

/// Determine if an entry is a value.
/// @entry: XArray entry.
///
/// Context: Any context.
/// Return: True if the entry is a value, false if it is a pointer.
const fn xa_is_value(entry: Va) -> bool {
    (entry.0 & 1) == 1
}

const fn xa_is_node(entry: Va) -> bool {
    xa_is_internal(entry) && entry.0 > 4096
}

const fn mt_flags_height(ma_flags: u32) -> u32 {
    const MT_FLAGS_HEIGHT_OFFSET: u32 = 0x02;
    const MT_FLAGS_HEIGHT_MASK: u32 = 0x7C;

    (ma_flags & MT_FLAGS_HEIGHT_MASK) >> MT_FLAGS_HEIGHT_OFFSET
}

/// We also reserve values with the bottom two bits set to '10' which are
/// below 4096
const fn mt_is_reserved(entry: Va /* void* */) -> bool {
    const MAPLE_RESERVED_RANGE: u64 = 4096;
    (entry.0 < MAPLE_RESERVED_RANGE) && xa_is_internal(entry)
}

const fn mt_node_max(entry: Va) -> Option<u64> {
    match mte_node_type(entry) {
        Some(MapleType::Dense) => Some(31),
        Some(MapleType::Leaf64) => Some(u64::MAX),
        Some(MapleType::Range64) => Some(u64::MAX),
        Some(MapleType::Arange64) => Some(u64::MAX),
        None => None,
    }
}

const fn mte_node_type(entry: Va /* maple_enode */) -> Option<MapleType> {
    const MAPLE_NODE_TYPE_MASK: u64 = 0x0F;
    const MAPLE_NODE_TYPE_SHIFT: u64 = 0x03;
    match (entry.0 >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK {
        0x00 => Some(MapleType::Dense),
        0x01 => Some(MapleType::Leaf64),
        0x02 => Some(MapleType::Range64),
        0x03 => Some(MapleType::Arange64),
        _ => None,
    }
}

const fn ma_is_leaf(typ: MapleType) -> bool {
    matches!(typ, MapleType::Dense | MapleType::Leaf64)
}

const fn mte_to_node(entry: Va /* maple_enode */) -> Va {
    const MAPLE_NODE_MASK: u64 = 255;
    Va::new(entry.0 & !MAPLE_NODE_MASK)
}

const fn mte_is_leaf(entry: Va /* maple_enode */) -> bool {
    match mte_node_type(entry) {
        Some(typ) => ma_is_leaf(typ),
        None => false,
    }
}

/// An iterator for traversing entries in a MapleTree
pub struct MapleTreeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The maple tree root VA
    root: Va,

    /// Current node
    node: Option<Va>,

    /// Current index
    index: u64,

    /// Current last value (for range)
    last: u64,

    /// Min value in current node
    min: u64,

    /// Max value in current node
    max: u64,

    /// Current offset in node
    offset: u8,

    /// Current node type
    node_type: Option<MapleType>,

    /// Whether initial setup has been done
    initialized: bool,
}

impl<'a, Driver> MapleTreeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Create a new MapleTreeIterator
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, root: Va) -> Self {
        Self {
            vmi,
            root,
            node: None,
            index: 0,
            last: u64::MAX,
            min: 0,
            max: u64::MAX,
            offset: 0,
            node_type: None,
            initialized: false,
        }
    }

    fn initialize(&mut self) -> Result<(), VmiError> {
        if self.initialized {
            return Ok(());
        }

        let offsets = &self.vmi.underlying_os().offsets;
        let __maple_tree = &offsets.maple_tree;

        let entry = self
            .vmi
            .read_va_native(self.root + __maple_tree.ma_root.offset())?;

        if !xa_is_node(entry) {
            // Handle non-node entry (direct value/zero entry)
            self.node = Some(entry);
        }
        else if !entry.is_null() {
            self.node = Some(entry);
            self.node_type = mte_node_type(entry);
            self.walk_to_first()?;
        }

        self.initialized = true;
        Ok(())
    }

    fn walk_to_first(&mut self) -> Result<(), VmiError> {
        while let Some(node) = self.node {
            if mte_is_leaf(node) {
                break;
            }

            let child = self.read_slot(0)?;
            if child.is_null() {
                break;
            }

            self.node = Some(child);
            self.node_type = mte_node_type(child);
            self.offset = 0;
        }
        Ok(())
    }

    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        let Some(current_node) = self.node
        else {
            return Ok(None);
        };

        // If we're at a non-node entry
        if !xa_is_node(current_node) {
            let entry = if xa_is_value(current_node) {
                Va::new(xa_to_value(current_node))
            }
            else if xa_is_zero(current_node) {
                Va::new(xa_to_internal(current_node))
            }
            else if !mt_is_reserved(current_node) {
                current_node
            }
            else {
                return Ok(None);
            };

            self.offset += 1; // Advance to next slot

            // Move to next entry in current node
            let next = match self.node_type {
                Some(MapleType::Dense) => self.walk_next_dense()?,
                Some(MapleType::Leaf64 | MapleType::Range64) => self.walk_next_range64()?,
                Some(MapleType::Arange64) => self.walk_next_arange64()?,
                None => None,
            };

            if let Some(next) = next {
                self.node = Some(next);
            }
            else {
                self.node = None;
            }

            return Ok(Some(entry));
        }

        // Handle node traversal based on type
        let next = match self.node_type {
            Some(MapleType::Dense) => self.walk_next_dense()?,
            Some(MapleType::Leaf64 | MapleType::Range64) => self.walk_next_range64()?,
            Some(MapleType::Arange64) => self.walk_next_arange64()?,
            None => return Ok(None),
        };

        if let Some(next) = next {
            self.node = Some(next);
            self.walk_next()
        }
        else {
            Ok(None)
        }
    }

    fn walk_next_dense(&mut self) -> Result<Option<Va>, VmiError> {
        let node = mte_to_node(self.node.unwrap());
        let offsets = &self.vmi.underlying_os().offsets;
        let __maple_node = &offsets.maple_node;

        // Get next non-null slot
        while self.offset < 31 {
            // MAPLE_NODE_SLOTS for 64-bit
            self.offset += 1;
            let slot = self
                .vmi
                .read_va_native(node + __maple_node.slot.offset() + (self.offset as u64 * 8))?;
            if !slot.is_null() {
                return Ok(Some(slot));
            }
        }

        self.node = None;
        Ok(None)
    }

    fn walk_next_range64(&mut self) -> Result<Option<Va>, VmiError> {
        let node = mte_to_node(self.node.unwrap());
        let offsets = &self.vmi.underlying_os().offsets;
        let __maple_node = &offsets.maple_node;
        let __maple_range_64 = &offsets.maple_range_64;

        let node = node + __maple_node.mr64.offset();

        // Check if we've reached end of current node
        if self.offset >= 16 {
            // MAPLE_RANGE64_SLOTS
            return Ok(None);
        }

        // Read current slot
        let slot = self
            .vmi
            .read_va_native(node + __maple_range_64.slot.offset() + (self.offset as u64 * 8))?;

        // Skip empty slots
        if slot.is_null() {
            return Ok(None);
        }

        // Get range end
        let last = if self.offset < 15 {
            self.vmi
                .read_u64(node + __maple_range_64.pivot.offset() + (self.offset as u64 * 8))?
        }
        else {
            self.max
        };

        self.last = last;

        if mte_is_leaf(self.node.unwrap()) {
            Ok(Some(slot))
        }
        else {
            // Descend into child node
            self.node = Some(slot);
            self.node_type = mte_node_type(slot);
            self.offset = 0;
            self.walk_to_first()?;
            self.walk_next()
        }
    }

    fn walk_next_arange64(&mut self) -> Result<Option<Va>, VmiError> {
        let node = mte_to_node(self.node.unwrap());
        let offsets = &self.vmi.underlying_os().offsets;
        let __maple_node = &offsets.maple_node;
        let __maple_arange_64 = &offsets.maple_arange_64;

        let node = node + __maple_node.ma64.offset();

        #[expect(clippy::never_loop)]
        while self.offset < 10 {
            // MAPLE_ARANGE64_SLOTS for 64-bit
            self.offset += 1;

            // Read slot and pivot
            let slot = self.vmi.read_va_native(
                node + __maple_arange_64.slot.offset() + (self.offset as u64 * 8),
            )?;

            if slot.is_null() {
                self.node = None;
                return Ok(None);
            }

            let last = if self.offset < 9 {
                self.vmi
                    .read_u64(node + __maple_arange_64.pivot.offset() + (self.offset as u64 * 8))?
            }
            else {
                self.max
            };

            self.last = last;
            if mte_is_leaf(self.node.unwrap()) {
                return Ok(Some(slot));
            }
            else {
                self.node = Some(slot);
                self.node_type = mte_node_type(slot);
                self.offset = 0;
                self.walk_to_first()?;
                return self.walk_next();
            }
        }

        self.node = None;
        Ok(None)
    }

    fn read_slot(&self, offset: u8) -> Result<Va, VmiError> {
        let node = mte_to_node(self.node.unwrap());
        let offsets = &self.vmi.underlying_os().offsets;
        let __maple_node = &offsets.maple_node;

        match self.node_type {
            Some(MapleType::Dense) => self
                .vmi
                .read_va_native(node + __maple_node.slot.offset() + (offset as u64 * 8)),
            Some(MapleType::Leaf64 | MapleType::Range64) => {
                let node = node + __maple_node.mr64.offset();
                self.vmi.read_va_native(
                    node + offsets.maple_range_64.slot.offset() + (offset as u64 * 8),
                )
            }
            Some(MapleType::Arange64) => {
                let node = node + __maple_node.ma64.offset();
                self.vmi.read_va_native(
                    node + offsets.maple_arange_64.slot.offset() + (offset as u64 * 8),
                )
            }
            None => Ok(Va(0)),
        }
    }
}

impl<Driver> Iterator for MapleTreeIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized
            && let Err(err) = self.initialize()
        {
            return Some(Err(err));
        }

        self.walk_next().transpose()
    }
}
