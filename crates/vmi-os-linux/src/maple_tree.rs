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
use vmi_core::{Architecture, Registers as _, Va, VmiDriver, VmiError, VmiState};

use crate::{arch::ArchAdapter, LinuxOs, Offsets};

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

/// A MapleTree traversal and manipulation implementation.
///
/// This struct provides methods for traversing and inspecting Linux kernel
/// Maple Trees, which are used primarily for managing virtual memory areas.
pub struct MapleTree<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: &'a VmiState<'a, Driver, LinuxOs<Driver>>,

    /// Offsets for the Maple Tree data structure.
    offsets: &'a Offsets,
}

impl<'a, Driver> MapleTree<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new MapleTree instance.
    pub fn new(vmi: &'a VmiState<Driver, LinuxOs<Driver>>, offsets: &'a Offsets) -> Self {
        Self { vmi, offsets }
    }

    // region: Enumerate

    /// Enumerates all entries in the Maple Tree.
    ///
    /// Traverses the tree structure and calls the provided callback for each entry found.
    pub fn enumerate(
        &self,
        root: Va,
        mut callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let __maple_tree = &self.offsets.maple_tree;

        let entry = self.vmi.read_va(root + __maple_tree.ma_root.offset)?;

        if !xa_is_node(entry) {
            self.enumerate_entry(entry, &mut callback);
        }
        else if !entry.is_null() {
            self.enumerate_node(root, entry, 0, u64::MAX, &mut callback)?;
        }

        Ok(())
    }

    fn enumerate_entry(&self, entry: Va, callback: &mut impl FnMut(Va) -> bool) {
        if xa_is_value(entry) {
            callback(Va(xa_to_value(entry)));
        }
        else if xa_is_zero(entry) {
            callback(Va(xa_to_internal(entry)));
        }
        else {
            callback(entry);
        }
    }

    fn enumerate_node(
        &self,
        mt: Va,
        entry: Va,
        min: u64,
        max: u64,
        callback: &mut impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let __maple_tree = &self.offsets.maple_tree;
        let __maple_node = &self.offsets.maple_node;

        let node = mte_to_node(entry);
        let typ = mte_node_type(entry);

        match typ {
            Some(MapleType::Dense) => {
                // const MAPLE_NODE_SLOTS: u64 = 63;   // 32 bit OS
                const MAPLE_NODE_SLOTS: u64 = 31; // 64 bit OS
                for i in 0..MAPLE_NODE_SLOTS {
                    let slot = self.vmi.read_va(node + __maple_node.slot.offset + i * 8)?;

                    if !slot.is_null() {
                        self.enumerate_entry(slot, callback);
                    }
                }
            }
            Some(MapleType::Leaf64 | MapleType::Range64) => {
                self.enumerate_range64(mt, entry, min, max, callback)?;
            }
            Some(MapleType::Arange64) => {
                self.enumerate_arange64(mt, entry, min, max, callback)?;
            }
            None => tracing::warn!(?typ, "Unknown node type"),
        }

        Ok(())
    }

    fn enumerate_range64(
        &self,
        mt: Va,
        entry: Va,
        min: u64,
        max: u64,
        callback: &mut impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let __maple_node = &self.offsets.maple_node;
        let __maple_range_64 = &self.offsets.maple_range_64;

        let node = mte_to_node(entry) + __maple_node.mr64.offset;
        let leaf = mte_is_leaf(entry);
        let mut first = min;

        const MAPLE_RANGE64_SLOTS_32: u64 = 32; // 32 bit OS
        const MAPLE_RANGE64_SLOTS_64: u64 = 16; // 64 bit OS

        #[allow(non_snake_case)]
        let MAPLE_RANGE64_SLOTS = match self.vmi.registers().address_width() {
            4 => MAPLE_RANGE64_SLOTS_32,
            8 => MAPLE_RANGE64_SLOTS_64,
            _ => 0,
        };

        let __pivot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_range_64.pivot.offset + offset)
                .map(u64::from)
        };

        let __slot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_range_64.slot.offset + offset)
        };

        for i in 0..MAPLE_RANGE64_SLOTS {
            let mut last = max;

            if i < (MAPLE_RANGE64_SLOTS - 1) {
                last = __pivot(i)?;
            }
            else {
                let slot = __slot(i)?;
                if slot.is_null() && Some(max) != mt_node_max(entry) {
                    break;
                }
            }

            if last == 0 && i > 0 {
                break;
            }

            let slot = __slot(i)?;

            if leaf {
                self.enumerate_entry(slot, callback)
            }
            else if !slot.is_null() {
                self.enumerate_node(mt, slot, first, last, callback)?;
            }

            if last == max {
                break;
            }

            first = last + 1;
        }

        Ok(())
    }

    fn enumerate_arange64(
        &self,
        mt: Va,
        entry: Va,
        min: u64,
        max: u64,
        callback: &mut impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let __maple_node = &self.offsets.maple_node;
        let __maple_arange_64 = &self.offsets.maple_arange_64;

        let node = mte_to_node(entry) + __maple_node.ma64.offset;
        let leaf = mte_is_leaf(entry);
        let mut first = min;

        const MAPLE_ARANGE64_SLOTS_32: u64 = 21; // 32 bit OS
        const MAPLE_ARANGE64_SLOTS_64: u64 = 10; // 64 bit OS

        #[allow(non_snake_case)]
        let MAPLE_ARANGE64_SLOTS = match self.vmi.registers().address_width() {
            4 => MAPLE_ARANGE64_SLOTS_32,
            8 => MAPLE_ARANGE64_SLOTS_64,
            _ => 0,
        };

        let __pivot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_arange_64.pivot.offset + offset)
                .map(u64::from)
        };

        let __slot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_arange_64.slot.offset + offset)
        };

        for i in 0..MAPLE_ARANGE64_SLOTS {
            let mut last = max;

            if i < (MAPLE_ARANGE64_SLOTS - 1) {
                last = __pivot(i)?;
            }
            else {
                let slot = __slot(i)?;
                if slot.is_null() {
                    break;
                }
            }

            if last == 0 && i > 0 {
                break;
            }

            let slot = __slot(i)?;

            if leaf {
                self.enumerate_entry(slot, callback)
            }
            else if !slot.is_null() {
                self.enumerate_node(mt, slot, first, last, callback)?;
            }

            if last == max {
                break;
            }

            first = last + 1;
        }

        Ok(())
    }

    // endregion

    // region: Dump

    /// Dumps the entire Maple Tree structure for debugging.
    pub fn dump(&self, mt: Va) -> Result<(), VmiError> {
        let __maple_tree = &self.offsets.maple_tree;

        let flags = self.vmi.read_u32(mt + __maple_tree.ma_flags.offset)?;
        let entry = self.vmi.read_va(mt + __maple_tree.ma_root.offset)?;

        println!(
            "maple_tree({}) flags {:X}, height {} root {:X}",
            mt,
            flags,
            mt_flags_height(flags),
            entry
        );

        if !xa_is_node(entry) {
            self.dump_entry(entry, 0, 0, 0);
        }
        else if !entry.is_null() {
            self.dump_node(mt, entry, 0, u64::MAX, 0)?;
        }

        Ok(())
    }

    fn dump_range(&self, min: u64, max: u64, depth: u64) {
        if min == max {
            println!("{:width$}{:X}: ", "", min, width = (depth * 2) as usize);
        }
        else {
            println!(
                "{:width$}{:X}-{:X}: ",
                "",
                min,
                max,
                width = (depth * 2) as usize
            );
        }
    }

    fn dump_entry(&self, entry: Va, _min: u64, _max: u64, depth: u64) {
        print!("{:width$}", "", width = (depth * 2) as usize);

        if xa_is_value(entry) {
            println!("Value: {:#x}", xa_to_value(entry));
        }
        else if xa_is_zero(entry) {
            println!("Zero: {:?}", xa_to_internal(entry));
        }
        else if mt_is_reserved(entry) {
            println!("Reserved: {:?}", entry);
        }
        else {
            println!("{:?}", entry);
            /*
            if entry.is_null() {
                return;
            }

            let __vm_area_struct = &self.offsets.vm_area_struct;
            let start = self.vmi.read_u64(entry + __vm_area_struct.vm_start.offset);
            let end = self.vmi.read_u64(entry + __vm_area_struct.vm_end.offset);
            let file = self.vmi.read_va(entry + __vm_area_struct.vm_file.offset);
            println!("Range: {:X?}-{:X?}", start, end);

            if let Ok(file) = file {
                if !file.is_null() {
                    let __dentry = &self.offsets.dentry;
                    let __file = &self.offsets.file;
                    let __path = &self.offsets.path;
                    let __qstr = &self.offsets.qstr;

                    let f_path = file + __file.f_path.offset;

                    if let Ok(dentry) = self.vmi.read_va(f_path + __path.dentry.offset) {
                        if let Ok(d_name) =
                            self.vmi.read_va(dentry + __dentry.d_name.offset + __qstr.name.offset)
                        {
                            let name = self.read_string(d_name);
                            println!("    File: {:?}", name);
                        }
                    }
                }
            }
            */
        }
    }

    fn dump_node(&self, mt: Va, entry: Va, min: u64, max: u64, depth: u64) -> Result<(), VmiError> {
        let __maple_tree = &self.offsets.maple_tree;
        let __maple_node = &self.offsets.maple_node;

        let node = mte_to_node(entry);
        let typ = mte_node_type(entry);

        self.dump_range(min, max, depth);

        println!(
            "node {:X} depth {} type {:?} parent {:?}",
            node,
            depth,
            mte_node_type(entry),
            if !node.is_null() {
                self.vmi.read_va(node + __maple_node.parent.offset)
            }
            else {
                Ok(Va::default())
            }
        );

        match typ {
            Some(MapleType::Dense) => {
                // const MAPLE_NODE_SLOTS: u64 = 63;   // 32 bit OS
                const MAPLE_NODE_SLOTS: u64 = 31; // 64 bit OS
                for i in 0..MAPLE_NODE_SLOTS {
                    let slot = self.vmi.read_va(node + __maple_node.slot.offset + i * 8)?;

                    if !slot.is_null() {
                        self.dump_entry(slot, min, max, depth);
                    }
                }
            }
            Some(MapleType::Leaf64 | MapleType::Range64) => {
                self.dump_range64(mt, entry, min, max, depth)?;
            }
            Some(MapleType::Arange64) => {
                self.dump_arange64(mt, entry, min, max, depth)?;
            }
            None => tracing::warn!(?typ, "Unknown node type"),
        }

        Ok(())
    }

    fn dump_range64(
        &self,
        mt: Va,
        entry: Va,
        min: u64,
        max: u64,
        depth: u64,
    ) -> Result<(), VmiError> {
        let __maple_node = &self.offsets.maple_node;
        let __maple_range_64 = &self.offsets.maple_range_64;

        let node = mte_to_node(entry) + __maple_node.mr64.offset;
        let leaf = mte_is_leaf(entry);
        let mut first = min;

        // const MAPLE_RANGE64_SLOTS: u64 = 32;   // 32 bit OS
        const MAPLE_RANGE64_SLOTS: u64 = 16; // 64 bit OS

        let __pivot = |i: u64| {
            let offset = i * size_of::<u64>() as u64;
            self.vmi
                .read_u64(node + __maple_range_64.pivot.offset + offset)
        };

        let __slot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_range_64.slot.offset + offset)
        };

        for i in 0..MAPLE_RANGE64_SLOTS - 1 {
            println!("pivot {:X} slot {:X}", __pivot(i)?, __slot(i)?);
        }
        println!("slot {:X}", __slot(MAPLE_RANGE64_SLOTS - 1)?);

        for i in 0..MAPLE_RANGE64_SLOTS {
            let mut last = max;

            if i < (MAPLE_RANGE64_SLOTS - 1) {
                last = __pivot(i)?;
            }
            else {
                let slot = __slot(i)?;
                if slot.is_null() && Some(max) != mt_node_max(entry) {
                    break;
                }
            }

            if last == 0 && i > 0 {
                break;
            }

            let slot = __slot(i)?;

            if leaf {
                self.dump_entry(slot, first, last, depth + 1)
            }
            else if !slot.is_null() {
                self.dump_node(mt, slot, first, last, depth + 1)?;
            }

            if last == max {
                break;
            }

            first = last + 1;
        }

        Ok(())
    }

    fn dump_arange64(
        &self,
        mt: Va,
        entry: Va,
        min: u64,
        max: u64,
        depth: u64,
    ) -> Result<(), VmiError> {
        let __maple_node = &self.offsets.maple_node;
        let __maple_arange_64 = &self.offsets.maple_arange_64;

        let node = mte_to_node(entry) + __maple_node.ma64.offset;
        let leaf = mte_is_leaf(entry);
        let mut first = min;

        // const MAPLE_ARANGE64_SLOTS: u64 = 21;   // 32 bit OS
        const MAPLE_ARANGE64_SLOTS: u64 = 10; // 64 bit OS

        let __pivot = |i: u64| {
            let offset = i * size_of::<u64>() as u64;
            self.vmi
                .read_u64(node + __maple_arange_64.pivot.offset + offset)
        };

        let __slot = |i: u64| {
            let offset = i * self.vmi.registers().address_width() as u64;
            self.vmi
                .read_va(node + __maple_arange_64.slot.offset + offset)
        };

        for i in 0..MAPLE_ARANGE64_SLOTS - 1 {
            println!("pivot {:X} slot {:X}", __pivot(i)?, __slot(i)?);
        }
        println!("slot {:X}", __slot(MAPLE_ARANGE64_SLOTS - 1)?);

        for i in 0..MAPLE_ARANGE64_SLOTS {
            let mut last = max;

            if i < (MAPLE_ARANGE64_SLOTS - 1) {
                last = __pivot(i)?;
            }
            else {
                let slot = __slot(i)?;
                if slot.is_null() {
                    break;
                }
            }

            if last == 0 && i > 0 {
                break;
            }

            let slot = __slot(i)?;

            if leaf {
                self.dump_entry(slot, first, last, depth + 1)
            }
            else if !slot.is_null() {
                self.dump_node(mt, slot, first, last, depth + 1)?;
            }

            if last == max {
                break;
            }

            first = last + 1;
        }

        Ok(())
    }

    // endregion
}
