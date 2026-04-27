use std::iter::FusedIterator;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

use crate::{
    ArchAdapter, WindowsError, WindowsHive, WindowsHiveCellIndex, WindowsKeyIndex, WindowsKeyNode,
    WindowsOs,
};

/// An iterator over the subkeys of one storage class of a `_CM_KEY_NODE`.
///
/// Walks a single `_CM_KEY_NODE.SubKeyLists[]` entry (stable or volatile)
/// and flattens the four `_CM_KEY_INDEX` variants (`il`, `fl`, `hl`, `ir`)
/// into a stream of [`WindowsKeyNode`]s.
pub struct KeyNodeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the owning `_CMHIVE`.
    hive_va: Va,

    /// Number of subkeys still to yield, per `_CM_KEY_NODE.SubKeyCounts`.
    remaining: u32,

    /// Top-level `_CM_KEY_INDEX` cell to walk. Comes from one of the
    /// `_CM_KEY_NODE.SubKeyLists[]` slots (stable or volatile).
    root: WindowsHiveCellIndex,

    /// Current top-level frame. Holds a leaf (`il`/`fl`/`hl`) or `ir`.
    outer: Option<Frame>,

    /// Leaf frame entered via an `ir` parent, if any.
    inner: Option<Frame>,

    /// Whether the iterator has been initialized.
    initialized: bool,
}

/// Walk state for one `_CM_KEY_INDEX` cell.
#[derive(Debug, Clone, Copy)]
struct Frame {
    /// Signature bytes read from the cell (`'il'`, `'fl'`, `'hl'`, `'ir'`).
    signature: u16,

    /// Address of the first entry in `_CM_KEY_INDEX.List[]`.
    entries_va: Va,

    /// Byte size of one entry. 4 for `il` and `ir`, 8 for `fl` and `hl`.
    entry_size: u64,

    /// Number of entries in the list.
    count: u16,

    /// Position of the next entry to read.
    position: u16,
}

impl<'a, Driver> KeyNodeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new subkey iterator for one storage class.
    pub fn new(
        vmi: VmiState<'a, WindowsOs<Driver>>,
        hive_va: Va,
        root: WindowsHiveCellIndex,
        count: u32,
    ) -> Self {
        Self {
            vmi,
            hive_va,
            remaining: count,
            root,
            outer: None,
            inner: None,
            initialized: false,
        }
    }

    /// Resolves an `HCELL_INDEX` against the owning hive.
    ///
    /// The kernel guarantees that every index reached during a subkey walk -
    /// whether a `_CM_KEY_NODE.SubKeyLists[]` slot or a `_CM_KEY_INDEX.List[]`
    /// entry - is a valid `HCELL_INDEX`.
    fn resolve(&self, index: WindowsHiveCellIndex) -> Result<Va, VmiError> {
        let hive = WindowsHive::new(self.vmi, self.hive_va);
        match hive.cell(index)? {
            Some(va) => Ok(va),
            None => Err(WindowsError::CorruptedStruct("CM_KEY_INDEX.List[]").into()),
        }
    }

    /// Reads a `_CM_KEY_INDEX` header and returns a fresh walk frame.
    ///
    /// Also recognises the single-subkey optimization, where `cell_va` is a
    /// `_CM_KEY_NODE` rather than a `_CM_KEY_INDEX`.
    fn load_frame(&self, cell_va: Va) -> Result<Frame, VmiError> {
        let signature = self.vmi.read_u16(cell_va)?;

        if matches!(
            signature,
            WindowsKeyNode::<Driver>::KEY_NODE_SIGNATURE
                | WindowsKeyNode::<Driver>::LINK_NODE_SIGNATURE
        ) {
            return Ok(Frame {
                signature,
                entries_va: cell_va,
                entry_size: 0,
                count: 1,
                position: 0,
            });
        }

        let index = WindowsKeyIndex::new(self.vmi, cell_va);

        // Avoid re-reading the signature in entry_size_for() by passing it explicitly.
        let entry_size = WindowsKeyIndex::<Driver>::entry_size_for(signature)?;
        let count = index.count()?;
        let entries_va = index.list()?;

        Ok(Frame {
            signature,
            entries_va,
            entry_size,
            count,
            position: 0,
        })
    }

    /// Reads the entry at `frame.position` from a leaf-like frame.
    ///
    /// Returns the address of the yielded `_CM_KEY_NODE`. For `kn` frames
    /// the node is the frame itself. For `il`/`fl`/`hl` frames it is resolved
    /// via the `HCELL_INDEX` at the current position. The frame is read-only -
    /// callers must advance `position` themselves before invoking this, so
    /// that a failed read does not replay the same entry on the next call.
    fn yield_from(&self, frame: &Frame) -> Result<Va, VmiError> {
        if matches!(
            frame.signature,
            WindowsKeyNode::<Driver>::KEY_NODE_SIGNATURE
                | WindowsKeyNode::<Driver>::LINK_NODE_SIGNATURE
        ) {
            return Ok(frame.entries_va);
        }

        let entry_va = frame.entries_va + frame.position as u64 * frame.entry_size;
        let hcell = self.vmi.read_u32(entry_va)?;
        self.resolve(WindowsHiveCellIndex::new(hcell))
    }

    /// Advances the walk and returns the next subkey, if any.
    fn walk_next(&mut self) -> Result<Option<WindowsKeyNode<'a, Driver>>, VmiError> {
        if !self.initialized {
            self.initialized = true;

            if !self.root.is_nil() {
                let root_va = self.resolve(self.root)?;
                self.outer = Some(self.load_frame(root_va)?);
            }
        }

        loop {
            if let Some(mut frame) = self.inner {
                if frame.position < frame.count {
                    let snapshot = frame;
                    frame.position += 1;
                    self.inner = Some(frame);
                    self.remaining = self.remaining.saturating_sub(1);

                    let va = self.yield_from(&snapshot)?;
                    return Ok(Some(WindowsKeyNode::new(self.vmi, self.hive_va, va)));
                }

                self.inner = None;
            }

            if let Some(mut frame) = self.outer {
                if frame.position < frame.count {
                    if frame.signature == WindowsKeyIndex::<Driver>::INDEX_ROOT_SIGNATURE {
                        let entry_va = frame.entries_va + frame.position as u64 * frame.entry_size;
                        frame.position += 1;
                        self.outer = Some(frame);

                        let raw = self.vmi.read_u32(entry_va)?;
                        let sub_va = self.resolve(WindowsHiveCellIndex::new(raw))?;
                        self.inner = Some(self.load_frame(sub_va)?);
                        continue;
                    }

                    let snapshot = frame;
                    frame.position += 1;
                    self.outer = Some(frame);
                    self.remaining = self.remaining.saturating_sub(1);

                    let va = self.yield_from(&snapshot)?;
                    return Ok(Some(WindowsKeyNode::new(self.vmi, self.hive_va, va)));
                }

                self.outer = None;
            }

            return Ok(None);
        }
    }
}

impl<'a, Driver> Iterator for KeyNodeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Item = Result<WindowsKeyNode<'a, Driver>, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.remaining as usize;
        (n, Some(n))
    }
}

impl<Driver> FusedIterator for KeyNodeIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}

impl<Driver> ExactSizeIterator for KeyNodeIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
}
