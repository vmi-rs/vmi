//! Walks over maple trees.
//!
//! The maple tree is the B-tree variant that holds the memory regions of a
//! process since Linux 6.1, in `mm_struct.mm_mt`. Its nodes are 256 bytes and
//! aligned to 256 bytes, and the low byte of a pointer to a node encodes the
//! node's type. The constants and rules here follow
//! `include/linux/maple_tree.h` and `lib/maple_tree.c`, which agree in Linux
//! 6.8 and 7.0.

use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{ArchAdapter, LinuxError, LinuxOs, offset};

/// Bits of an encoded node pointer below the node's address
/// (`MAPLE_NODE_MASK`).
const MAPLE_NODE_MASK: u64 = 0xff;

/// Position of the node type in an encoded node pointer
/// (`MAPLE_NODE_TYPE_SHIFT`).
const MAPLE_NODE_TYPE_SHIFT: u64 = 3;

/// Mask of the node type after the shift (`MAPLE_NODE_TYPE_MASK`).
const MAPLE_NODE_TYPE_MASK: u64 = 0x0f;

/// Size and alignment of a node.
const MAPLE_NODE_SIZE: usize = 256;

/// Pivots in a `maple_range_64` node, which shares its layout with
/// `maple_leaf_64`.
const MAPLE_RANGE64_PIVOTS: usize = 15;

/// Number of slots of a `maple_range_64` node (`MAPLE_RANGE64_SLOTS`).
const MAPLE_RANGE64_SLOTS: usize = 16;

/// Number of pivots of a `maple_arange_64` node.
const MAPLE_ARANGE64_PIVOTS: usize = 9;

/// Number of slots of a `maple_arange_64` node (`MAPLE_ARANGE64_SLOTS`).
const MAPLE_ARANGE64_SLOTS: usize = 10;

/// Maximum tree height that the height bits of `maple_tree.ma_flags`
/// (`MT_FLAGS_HEIGHT_MASK`) can hold.
const MAPLE_HEIGHT_MAX: usize = 31;

/// Upper limit of the nodes that one walk reads, a guard against a corrupt
/// tree.
const MAPLE_NODES_MAX: usize = 1 << 20;

/// Type of a maple tree node.
///
/// Corresponds to `enum maple_type`, without `maple_dense`, which the trees
/// of memory regions do not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapleType {
    /// `maple_leaf_64`, a leaf with 64-bit pivots.
    Leaf64,

    /// `maple_range_64`, an inner node with 64-bit pivots.
    Range64,

    /// `maple_arange_64`, an inner node of an allocation tree, which also
    /// tracks the gaps below it.
    Arange64,
}

impl MapleType {
    /// Decodes the type of an encoded node pointer.
    fn from_encoded(entry: u64) -> Result<Self, VmiError> {
        match (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK {
            1 => Ok(Self::Leaf64),
            2 => Ok(Self::Range64),
            3 => Ok(Self::Arange64),
            _ => Err(LinuxError::CorruptedStruct("maple node type").into()),
        }
    }

    /// Checks if the slots of the node hold entries rather than child nodes.
    fn is_leaf(self) -> bool {
        matches!(self, Self::Leaf64)
    }

    /// Returns the number of pivots of the node type (`mt_pivots`).
    pub(crate) fn pivots(self) -> usize {
        match self {
            Self::Leaf64 | Self::Range64 => MAPLE_RANGE64_PIVOTS,
            Self::Arange64 => MAPLE_ARANGE64_PIVOTS,
        }
    }

    /// Returns the number of slots of the node type (`mt_slots`).
    pub(crate) fn slots(self) -> usize {
        match self {
            Self::Leaf64 | Self::Range64 => MAPLE_RANGE64_SLOTS,
            Self::Arange64 => MAPLE_ARANGE64_SLOTS,
        }
    }
}

/// The parts of a maple tree node that a walk reads.
#[derive(Debug, Clone, Default)]
pub(crate) struct MapleNode {
    /// Inclusive upper bounds of the slots. The node type tells how many are
    /// used.
    pub(crate) pivots: [u64; MAPLE_RANGE64_PIVOTS],

    /// Child nodes or entries. The node type tells how many are used.
    pub(crate) slots: [u64; MAPLE_RANGE64_SLOTS],

    /// `meta.end`, the last used slot when the last pivot is zero.
    pub(crate) meta_end: u8,
}

/// Source of maple tree nodes.
pub(crate) trait MapleNodeReader {
    /// Reads the node at the given address.
    fn read_node(&self, node: Va, ty: MapleType) -> Result<MapleNode, VmiError>;
}

/// Checks if an entry is internal to the tree, such as a node pointer or
/// `XA_ZERO_ENTRY` (`xa_is_internal`).
fn xa_is_internal(entry: u64) -> bool {
    (entry & 3) == 2
}

/// Checks if a root entry points to a node (`xa_is_node`).
fn xa_is_node(entry: u64) -> bool {
    xa_is_internal(entry) && entry > 4096
}

/// Returns the address of the node that an encoded node pointer points to
/// (`mte_to_node`).
fn node_address(entry: u64) -> Va {
    Va(entry & !MAPLE_NODE_MASK)
}

/// Returns the last used slot of a node, as `ma_data_end` computes it.
///
/// An allocation tree node keeps it in `meta.end`. Other nodes keep it there
/// only when their last pivot is zero. A last pivot equal to the node's
/// maximum ends the node one slot early, and any other value means that all
/// slots are used.
fn data_end(node: &MapleNode, ty: MapleType, max: u64) -> Result<usize, VmiError> {
    let end = match ty {
        MapleType::Arange64 => usize::from(node.meta_end),
        MapleType::Leaf64 | MapleType::Range64 => {
            let last = ty.pivots() - 1;

            if node.pivots[last] == 0 {
                usize::from(node.meta_end)
            }
            else if node.pivots[last] == max {
                last
            }
            else {
                ty.pivots()
            }
        }
    };

    if end >= ty.slots() {
        return Err(LinuxError::CorruptedStruct("maple node end").into());
    }

    Ok(end)
}

/// One node on the path from the root to the current entry.
struct MapleFrame {
    /// The node.
    node: MapleNode,

    /// The node's type.
    ty: MapleType,

    /// The highest index that the node covers.
    max: u64,

    /// The next slot to visit.
    offset: usize,

    /// The last used slot.
    end: usize,
}

/// Checks the guards against a corrupt tree before a walk reads one more
/// node, at the given depth and with the given count of nodes read.
fn check_walk_limits(depth: usize, nodes: usize) -> Result<(), VmiError> {
    if depth >= MAPLE_HEIGHT_MAX {
        return Err(LinuxError::CorruptedStruct("maple tree height").into());
    }

    if nodes > MAPLE_NODES_MAX {
        return Err(LinuxError::CorruptedStruct("maple tree size").into());
    }

    Ok(())
}

impl MapleFrame {
    /// Reads the node of an encoded node pointer, with the highest index
    /// that the node covers, and starts at its first slot.
    fn read<Reader>(reader: &Reader, entry: u64, max: u64) -> Result<Self, VmiError>
    where
        Reader: MapleNodeReader,
    {
        let ty = MapleType::from_encoded(entry)?;
        let node = reader.read_node(node_address(entry), ty)?;
        let end = data_end(&node, ty, max)?;

        Ok(Self {
            node,
            ty,
            max,
            offset: 0,
            end,
        })
    }

    /// Returns the highest index that a slot covers.
    ///
    /// The last used slot and the slots without a pivot reach up to the
    /// node's maximum.
    fn slot_max(&self, offset: usize) -> u64 {
        if offset < self.ty.pivots() && self.node.pivots[offset] != 0 {
            self.node.pivots[offset]
        }
        else {
            self.max
        }
    }

    /// Returns the slot that covers an index, as `mtree_lookup_walk` finds
    /// it.
    ///
    /// The first used slot whose pivot is at or above the index covers it.
    /// Without one, the last used slot does.
    fn slot_of(&self, index: u64) -> usize {
        (0..self.end)
            .find(|offset| self.node.pivots[*offset] >= index)
            .unwrap_or(self.end)
    }
}

/// Depth-first walk over the entries of a maple tree.
pub(crate) struct MapleWalk<Reader> {
    /// Source of the nodes.
    reader: Reader,

    /// The root entry, until the walk starts.
    root: Option<u64>,

    /// The path from the root to the current node.
    stack: Vec<MapleFrame>,

    /// Number of nodes read so far.
    nodes: usize,
}

impl<Reader> MapleWalk<Reader>
where
    Reader: MapleNodeReader,
{
    /// Creates a walk over the tree with the given root entry
    /// (`maple_tree.ma_root`).
    pub(crate) fn new(reader: Reader, root: u64) -> Self {
        Self {
            reader,
            root: Some(root),
            stack: Vec::new(),
            nodes: 0,
        }
    }

    /// Reads a node and puts it on top of the path.
    fn push(&mut self, entry: u64, max: u64) -> Result<(), VmiError> {
        self.nodes += 1;
        check_walk_limits(self.stack.len(), self.nodes)?;

        let frame = MapleFrame::read(&self.reader, entry, max)?;
        self.stack.push(frame);

        Ok(())
    }

    /// Returns the next entry in index order.
    ///
    /// Gaps (`NULL`) and internal entries are skipped.
    pub(crate) fn next_entry(&mut self) -> Result<Option<Va>, VmiError> {
        if let Some(root) = self.root.take() {
            if xa_is_node(root) {
                self.push(root, u64::MAX)?;
            }
            else if root != 0 && !xa_is_internal(root) {
                // A tree with a single entry at index 0 keeps it in the root.
                return Ok(Some(Va(root)));
            }
        }

        loop {
            let frame = match self.stack.last_mut() {
                Some(frame) => frame,
                None => return Ok(None),
            };

            if frame.offset > frame.end {
                self.stack.pop();
                continue;
            }

            let offset = frame.offset;
            frame.offset += 1;

            let entry = frame.node.slots[offset];

            if frame.ty.is_leaf() {
                if entry == 0 || xa_is_internal(entry) {
                    continue;
                }

                return Ok(Some(Va(entry)));
            }

            if entry == 0 {
                return Err(LinuxError::CorruptedStruct("maple node slot").into());
            }

            let max = frame.slot_max(offset);
            self.push(entry, max)?;
        }
    }
}

/// Returns the entry that covers an index, as `mtree_lookup_walk` finds it.
///
/// Returns `None` for an index in a gap.
pub(crate) fn maple_tree_lookup<Reader>(
    reader: &Reader,
    root: u64,
    index: u64,
) -> Result<Option<Va>, VmiError>
where
    Reader: MapleNodeReader,
{
    if !xa_is_node(root) {
        if index == 0 && root != 0 && !xa_is_internal(root) {
            return Ok(Some(Va(root)));
        }

        return Ok(None);
    }

    let mut entry = root;

    for _ in 0..MAPLE_HEIGHT_MAX {
        let ty = MapleType::from_encoded(entry)?;
        let node = reader.read_node(node_address(entry), ty)?;

        // Unused pivots are zero, so the first pivot at or above the index
        // marks the slot. Without one, the index falls into the last slot.
        let offset = node.pivots[..ty.pivots()]
            .iter()
            .position(|pivot| *pivot >= index)
            .unwrap_or(ty.pivots());

        let next = node.slots[offset];

        if ty.is_leaf() {
            if next == 0 || xa_is_internal(next) {
                return Ok(None);
            }

            return Ok(Some(Va(next)));
        }

        if next == 0 {
            return Err(LinuxError::CorruptedStruct("maple node slot").into());
        }

        entry = next;
    }

    Err(LinuxError::CorruptedStruct("maple tree height").into())
}

/// Direction of [`maple_tree_lookup_nearest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nearest {
    /// The entry that covers the index, or else the nearest one below it.
    Below,

    /// The entry that covers the index, or else the nearest one above it.
    Above,
}

/// Returns the entry that covers an index or, for an index in a gap, the
/// nearest entry in the given direction.
///
/// The walk descends to the leaf of the index, as [`maple_tree_lookup`]
/// does, and steps through the slots from there. When a node runs out of
/// slots, the walk climbs to the parent and descends the neighbouring slot
/// to its last or first entry. Returns `None` when no entry lies in that
/// direction.
pub(crate) fn maple_tree_lookup_nearest<Reader>(
    reader: &Reader,
    root: u64,
    index: u64,
    nearest: Nearest,
) -> Result<Option<Va>, VmiError>
where
    Reader: MapleNodeReader,
{
    if !xa_is_node(root) {
        // A tree with a single entry at index 0 keeps it in the root.
        if root == 0 || xa_is_internal(root) {
            return Ok(None);
        }

        return match nearest {
            Nearest::Below => Ok(Some(Va(root))),
            Nearest::Above if index == 0 => Ok(Some(Va(root))),
            Nearest::Above => Ok(None),
        };
    }

    let mut path = Vec::new();
    let mut nodes = 0;

    // Descend to the leaf that covers the index.
    let mut entry = root;
    let mut max = u64::MAX;

    loop {
        nodes += 1;
        check_walk_limits(path.len(), nodes)?;

        let mut frame = MapleFrame::read(reader, entry, max)?;
        frame.offset = frame.slot_of(index);

        let is_leaf = frame.ty.is_leaf();
        let child = frame.node.slots[frame.offset];
        let child_max = frame.slot_max(frame.offset);
        path.push(frame);

        if is_leaf {
            break;
        }

        if child == 0 {
            return Err(LinuxError::CorruptedStruct("maple node slot").into());
        }

        entry = child;
        max = child_max;
    }

    // Step through the slots, from the leaf's slot of the index on.
    loop {
        let frame = match path.last_mut() {
            Some(frame) => frame,
            None => return Ok(None),
        };

        let offset = frame.offset;
        let slot = frame.node.slots[offset];

        if !frame.ty.is_leaf() {
            if slot == 0 {
                return Err(LinuxError::CorruptedStruct("maple node slot").into());
            }

            let child_max = frame.slot_max(offset);

            nodes += 1;
            check_walk_limits(path.len(), nodes)?;

            let mut child = MapleFrame::read(reader, slot, child_max)?;
            child.offset = match nearest {
                Nearest::Below => child.end,
                Nearest::Above => 0,
            };

            path.push(child);
            continue;
        }

        if slot != 0 && !xa_is_internal(slot) {
            return Ok(Some(Va(slot)));
        }

        // Move to the neighbouring slot, and climb out of the nodes that
        // have none left.
        loop {
            let frame = match path.last_mut() {
                Some(frame) => frame,
                None => return Ok(None),
            };

            match nearest {
                Nearest::Below if frame.offset > 0 => {
                    frame.offset -= 1;
                    break;
                }
                Nearest::Above if frame.offset < frame.end => {
                    frame.offset += 1;
                    break;
                }
                Nearest::Below | Nearest::Above => {
                    path.pop();
                }
            }
        }
    }
}

/// Reads maple tree nodes from guest memory.
pub(crate) struct GuestMapleNodeReader<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,
}

impl<'a, Driver> GuestMapleNodeReader<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a reader of the guest's maple tree nodes.
    pub(crate) fn new(vmi: VmiState<'a, LinuxOs<Driver>>) -> Self {
        Self { vmi }
    }
}

impl<Driver> MapleNodeReader for GuestMapleNodeReader<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn read_node(&self, node: Va, ty: MapleType) -> Result<MapleNode, VmiError> {
        let MAPLE_RANGE_64 = offset!(self.vmi, maple_range_64);
        let MAPLE_ARANGE_64 = offset!(self.vmi, maple_arange_64);
        let MAPLE_METADATA = offset!(self.vmi, maple_metadata);

        let (pivot, slot, meta) = match ty {
            MapleType::Leaf64 | MapleType::Range64 => (
                &MAPLE_RANGE_64.pivot,
                &MAPLE_RANGE_64.slot,
                &MAPLE_RANGE_64.meta,
            ),
            MapleType::Arange64 => (
                &MAPLE_ARANGE_64.pivot,
                &MAPLE_ARANGE_64.slot,
                &MAPLE_ARANGE_64.meta,
            ),
        };

        // A node never crosses a page, so one read gets all of it.
        let mut buffer = [0u8; MAPLE_NODE_SIZE];
        self.vmi.read(node, &mut buffer)?;

        let mut result = MapleNode::default();

        for (index, value) in result.pivots.iter_mut().take(ty.pivots()).enumerate() {
            *value = node_u64(&buffer, pivot.offset() as usize + index * size_of::<u64>())?;
        }

        for (index, value) in result.slots.iter_mut().take(ty.slots()).enumerate() {
            *value = node_u64(&buffer, slot.offset() as usize + index * size_of::<u64>())?;
        }

        let meta_end = meta.offset() as usize + MAPLE_METADATA.end.offset() as usize;
        result.meta_end = match buffer.get(meta_end) {
            Some(meta_end) => *meta_end,
            None => return Err(LinuxError::UnsupportedProfile("maple node layout").into()),
        };

        Ok(result)
    }
}

/// Reads a 64-bit value at an offset of a node buffer.
fn node_u64(buffer: &[u8], offset: usize) -> Result<u64, VmiError> {
    match buffer.get(offset..offset + size_of::<u64>()) {
        Some(bytes) => {
            let mut value = [0u8; size_of::<u64>()];
            value.copy_from_slice(bytes);
            Ok(u64::from_le_bytes(value))
        }
        None => Err(LinuxError::UnsupportedProfile("maple node layout").into()),
    }
}

/// Iterator over the entries of a maple tree in guest memory.
///
/// The iterator yields the entries in the order of their indexes and skips
/// gaps (`NULL`) and the tree's internal entries. For `mm_struct.mm_mt`, the
/// entries are `vm_area_struct` pointers in the order of their addresses.
///
/// The iterator ends after the first error.
pub struct MapleTreeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `maple_tree` structure.
    tree: Va,

    /// The walk, from the first call to `next` on.
    walk: Option<MapleWalk<GuestMapleNodeReader<'a, Driver>>>,

    /// Whether the iteration is over.
    done: bool,
}

impl<'a, Driver> MapleTreeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new iterator over the maple tree at the given address.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, tree: Va) -> Self {
        Self {
            vmi,
            tree,
            walk: None,
            done: false,
        }
    }

    /// Reads the root entry of the tree.
    ///
    /// Corresponds to `maple_tree.ma_root`.
    fn root(&self) -> Result<u64, VmiError> {
        let MAPLE_TREE = offset!(self.vmi, maple_tree);

        self.vmi.read_u64(self.tree + MAPLE_TREE.ma_root.offset())
    }

    /// Walks to the next entry.
    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        if self.walk.is_none() {
            let root = self.root()?;
            self.walk = Some(MapleWalk::new(GuestMapleNodeReader::new(self.vmi), root));
        }

        match &mut self.walk {
            Some(walk) => walk.next_entry(),
            None => Ok(None),
        }
    }
}

impl<Driver> Iterator for MapleTreeIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.walk_next() {
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

impl<Driver> FusedIterator for MapleTreeIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// `XA_ZERO_ENTRY`, the internal entry `xa_mk_internal(257)`.
    const XA_ZERO_ENTRY: u64 = (257 << 2) | 2;

    /// Nodes of a tree built by hand, indexed by their addresses.
    #[derive(Default)]
    struct Tree {
        /// The nodes and their types.
        nodes: HashMap<u64, (MapleType, MapleNode)>,
    }

    impl Tree {
        /// Adds a node and returns its encoded pointer, as `mt_mk_node`
        /// builds it.
        fn add(
            &mut self,
            address: u64,
            ty: MapleType,
            pivots: &[u64],
            slots: &[u64],
            meta_end: u8,
        ) -> u64 {
            let mut node = MapleNode {
                meta_end,
                ..MapleNode::default()
            };
            node.pivots[..pivots.len()].copy_from_slice(pivots);
            node.slots[..slots.len()].copy_from_slice(slots);
            self.nodes.insert(address, (ty, node));

            let ty_bits = match ty {
                MapleType::Leaf64 => 1,
                MapleType::Range64 => 2,
                MapleType::Arange64 => 3,
            };

            address | (ty_bits << MAPLE_NODE_TYPE_SHIFT) | 0x04
        }

        /// Returns all entries of a walk from the given root.
        fn walk(&self, root: u64) -> Result<Vec<u64>, VmiError> {
            let mut walk = MapleWalk::new(self, root);
            let mut entries = Vec::new();

            while let Some(entry) = walk.next_entry()? {
                entries.push(entry.0);
            }

            Ok(entries)
        }

        /// Looks an index up from the given root.
        fn lookup(&self, root: u64, index: u64) -> Result<Option<u64>, VmiError> {
            Ok(maple_tree_lookup(&self, root, index)?.map(|entry| entry.0))
        }

        /// Looks up the nearest entry from the given root.
        fn nearest(
            &self,
            root: u64,
            index: u64,
            nearest: Nearest,
        ) -> Result<Option<u64>, VmiError> {
            Ok(maple_tree_lookup_nearest(&self, root, index, nearest)?.map(|entry| entry.0))
        }
    }

    impl MapleNodeReader for &Tree {
        fn read_node(&self, node: Va, ty: MapleType) -> Result<MapleNode, VmiError> {
            match self.nodes.get(&node.0) {
                Some((node_ty, node)) if *node_ty == ty => Ok(node.clone()),
                Some(_) => Err(VmiError::Other("node type mismatch")),
                None => Err(VmiError::Other("no such node")),
            }
        }
    }

    /// Turns an encoded node pointer into a root entry (`mte_mk_root`).
    fn root(node: u64) -> u64 {
        node | 0x02
    }

    #[test]
    fn empty_tree_has_no_entries() -> Result<(), VmiError> {
        let tree = Tree::default();

        assert_eq!(tree.walk(0)?, Vec::<u64>::new());
        assert_eq!(tree.lookup(0, 0x1000)?, None);
        Ok(())
    }

    #[test]
    fn single_entry_lives_in_the_root() -> Result<(), VmiError> {
        let tree = Tree::default();

        assert_eq!(tree.walk(0xa000)?, vec![0xa000]);
        assert_eq!(tree.lookup(0xa000, 0)?, Some(0xa000));
        assert_eq!(tree.lookup(0xa000, 1)?, None);
        Ok(())
    }

    #[test]
    fn leaf_root_skips_gaps() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        // Slots 0, 2 and 4 are gaps. The last pivot is zero, so meta.end
        // tells the last used slot.
        let leaf = tree.add(
            0x10000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff, 0x2fff, 0x3fff, u64::MAX],
            &[0, 0xa000, 0, 0xb000, 0],
            4,
        );
        let root = root(leaf);

        assert_eq!(tree.walk(root)?, vec![0xa000, 0xb000]);
        assert_eq!(tree.lookup(root, 0x0800)?, None);
        assert_eq!(tree.lookup(root, 0x1000)?, Some(0xa000));
        assert_eq!(tree.lookup(root, 0x1fff)?, Some(0xa000));
        assert_eq!(tree.lookup(root, 0x2000)?, None);
        assert_eq!(tree.lookup(root, 0x3abc)?, Some(0xb000));
        assert_eq!(tree.lookup(root, 0x7fff_0000)?, None);
        Ok(())
    }

    #[test]
    fn allocation_tree_visits_leaves_in_order() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        let left = tree.add(
            0x21000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff, 0x4fff],
            &[0, 0xa000, 0xb000],
            2,
        );
        let right = tree.add(
            0x22000,
            MapleType::Leaf64,
            &[0x5fff, 0x6fff, u64::MAX],
            &[0xc000, 0, 0xd000],
            2,
        );
        let inner = tree.add(
            0x20000,
            MapleType::Arange64,
            &[0x4fff, u64::MAX],
            &[left, right],
            1,
        );
        let root = root(inner);

        assert_eq!(tree.walk(root)?, vec![0xa000, 0xb000, 0xc000, 0xd000]);
        assert_eq!(tree.lookup(root, 0x1800)?, Some(0xa000));
        assert_eq!(tree.lookup(root, 0x4fff)?, Some(0xb000));
        assert_eq!(tree.lookup(root, 0x5000)?, Some(0xc000));
        assert_eq!(tree.lookup(root, 0x6800)?, None);
        assert_eq!(tree.lookup(root, 0x9000_0000)?, Some(0xd000));
        Ok(())
    }

    #[test]
    fn full_leaf_uses_its_last_slot() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        // A full leaf below a parent that limits it to 0x10ffff. Its last
        // pivot is neither zero nor the maximum, so all 16 slots are used.
        let pivots = (0..15)
            .map(|index| 0x1000 * index + 0xfff)
            .collect::<Vec<_>>();
        let slots = (0..16)
            .map(|index| 0x100_0000 + 0x100 * index)
            .collect::<Vec<_>>();
        let leaf = tree.add(0x31000, MapleType::Leaf64, &pivots, &slots, 0);
        let other = tree.add(0x32000, MapleType::Leaf64, &[u64::MAX], &[0xe000], 0);
        let inner = tree.add(
            0x30000,
            MapleType::Arange64,
            &[0x10_ffff, u64::MAX],
            &[leaf, other],
            1,
        );

        let mut expected = slots.clone();
        expected.push(0xe000);

        assert_eq!(tree.walk(root(inner))?, expected);
        assert_eq!(tree.lookup(root(inner), 0x10_0000)?, Some(slots[15]));
        Ok(())
    }

    #[test]
    fn last_pivot_at_the_maximum_ends_a_node_early() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        // The last pivot equals the node's maximum, so slot 15 is unused
        // even though it is not zero.
        let mut pivots = (0..14)
            .map(|index| 0x1000 * index + 0xfff)
            .collect::<Vec<_>>();
        pivots.push(0x10_ffff);
        let mut slots = (0..15)
            .map(|index| 0x100_0000 + 0x100 * index)
            .collect::<Vec<_>>();
        slots.push(0xdead_0000);
        let leaf = tree.add(0x41000, MapleType::Leaf64, &pivots, &slots, 0);
        let other = tree.add(0x42000, MapleType::Leaf64, &[u64::MAX], &[0xe000], 0);
        let inner = tree.add(
            0x40000,
            MapleType::Arange64,
            &[0x10_ffff, u64::MAX],
            &[leaf, other],
            1,
        );

        let entries = tree.walk(root(inner))?;
        assert!(!entries.contains(&0xdead_0000));
        assert_eq!(entries.len(), 16);
        Ok(())
    }

    #[test]
    fn zero_entries_are_skipped() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        let leaf = tree.add(
            0x50000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff, u64::MAX],
            &[0xa000, XA_ZERO_ENTRY, 0xb000],
            2,
        );
        let root = root(leaf);

        assert_eq!(tree.walk(root)?, vec![0xa000, 0xb000]);
        assert_eq!(tree.lookup(root, 0x1800)?, None);
        Ok(())
    }

    #[test]
    fn node_that_points_to_itself_ends_with_an_error() {
        let mut tree = Tree::default();

        // The inner node's first slot points back to the node itself.
        let encoded = 0x60000 | (3 << MAPLE_NODE_TYPE_SHIFT) | 0x04;
        tree.add(0x60000, MapleType::Arange64, &[u64::MAX], &[encoded], 0);

        assert!(tree.walk(root(encoded)).is_err());
        assert!(tree.lookup(root(encoded), 0x1000).is_err());
        assert!(tree.nearest(root(encoded), 0x1000, Nearest::Below).is_err());
    }

    #[test]
    fn nearest_steps_over_gaps_in_a_leaf() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        let leaf = tree.add(
            0x90000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff, 0x2fff, 0x3fff, u64::MAX],
            &[0, 0xa000, 0, 0xb000, 0],
            4,
        );
        let root = root(leaf);

        assert_eq!(tree.nearest(root, 0x0800, Nearest::Below)?, None);
        assert_eq!(tree.nearest(root, 0x0800, Nearest::Above)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x1800, Nearest::Below)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x1800, Nearest::Above)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x2800, Nearest::Below)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x2800, Nearest::Above)?, Some(0xb000));
        assert_eq!(
            tree.nearest(root, 0x7fff_0000, Nearest::Below)?,
            Some(0xb000)
        );
        assert_eq!(tree.nearest(root, 0x7fff_0000, Nearest::Above)?, None);
        Ok(())
    }

    #[test]
    fn nearest_crosses_into_the_neighbouring_leaf() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        // The left leaf ends with a gap, and the right one starts with one.
        let left = tree.add(
            0xa1000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff, 0x4fff],
            &[0xa000, 0xb000, 0],
            2,
        );
        let right = tree.add(
            0xa2000,
            MapleType::Leaf64,
            &[0x5fff, 0x6fff, u64::MAX],
            &[0, 0xc000, 0xd000],
            2,
        );
        let inner = tree.add(
            0xa0000,
            MapleType::Arange64,
            &[0x4fff, u64::MAX],
            &[left, right],
            1,
        );
        let root = root(inner);

        assert_eq!(tree.nearest(root, 0x3000, Nearest::Below)?, Some(0xb000));
        assert_eq!(tree.nearest(root, 0x3000, Nearest::Above)?, Some(0xc000));
        assert_eq!(tree.nearest(root, 0x5800, Nearest::Below)?, Some(0xb000));
        assert_eq!(tree.nearest(root, 0x5800, Nearest::Above)?, Some(0xc000));
        assert_eq!(tree.nearest(root, 0, Nearest::Below)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x8000, Nearest::Above)?, Some(0xd000));
        Ok(())
    }

    #[test]
    fn nearest_skips_a_leaf_without_entries() -> Result<(), VmiError> {
        let mut tree = Tree::default();

        let left = tree.add(
            0xb1000,
            MapleType::Leaf64,
            &[0x0fff, 0x1fff],
            &[0xa000, 0],
            1,
        );
        let middle = tree.add(0xb2000, MapleType::Leaf64, &[0x2fff, 0x3fff], &[0, 0], 1);
        let right = tree.add(
            0xb3000,
            MapleType::Leaf64,
            &[0x4fff, u64::MAX],
            &[0, 0xc000],
            1,
        );
        let inner = tree.add(
            0xb0000,
            MapleType::Arange64,
            &[0x1fff, 0x3fff, u64::MAX],
            &[left, middle, right],
            2,
        );
        let root = root(inner);

        assert_eq!(tree.nearest(root, 0x4800, Nearest::Below)?, Some(0xa000));
        assert_eq!(tree.nearest(root, 0x1800, Nearest::Above)?, Some(0xc000));
        Ok(())
    }

    #[test]
    fn nearest_with_one_entry_in_the_root() -> Result<(), VmiError> {
        let tree = Tree::default();

        assert_eq!(tree.nearest(0xa000, 0x5000, Nearest::Below)?, Some(0xa000));
        assert_eq!(tree.nearest(0xa000, 0, Nearest::Above)?, Some(0xa000));
        assert_eq!(tree.nearest(0xa000, 1, Nearest::Above)?, None);
        assert_eq!(tree.nearest(0, 0x5000, Nearest::Below)?, None);
        Ok(())
    }

    #[test]
    fn unknown_node_type_is_an_error() {
        let tree = Tree::default();

        // Type 0 is `maple_dense`, which memory region trees never use.
        let dense = root(0x70000 | 0x04);

        assert!(tree.walk(dense).is_err());
        assert!(tree.lookup(dense, 0).is_err());
    }
}
