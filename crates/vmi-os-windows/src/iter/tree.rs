use std::iter::FusedIterator;

use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use crate::{offsets::OffsetsExt, ArchAdapter, WindowsOs};

/// An iterator for traversing tree nodes.
///
/// Iterate over nodes in a tree-like structure, specifically `MMADDRESS_NODE`
/// (Windows 7) and `RTL_BALANCED_NODE` (Windows 8.1+).
pub struct TreeNodeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// Current node.
    current: Option<Va>,

    /// Root node.
    root: Va,

    /// Offset to the left child pointer.
    ///
    /// Either `MMADDRESS_NODE.LeftChild` or `RTL_BALANCED_NODE.Left`.
    offset_left: u64,

    /// Offset to the right child pointer.
    ///
    /// Either `MMADDRESS_NODE.RightChild` or `RTL_BALANCED_NODE.Right`.
    offset_right: u64,

    /// Offset to the parent pointer.
    ///
    /// Either `MMADDRESS_NODE.Parent` or `RTL_BALANCED_NODE.ParentValue`.
    offset_parent: u64,

    /// Whether the iterator has been initialized.
    initialized: bool,
}

impl<'a, Driver> TreeNodeIterator<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new tree node iterator.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, root: Va) -> Self {
        let offsets = &vmi.underlying_os().offsets;

        let (offset_left, offset_right, offset_parent) = match &offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

                (
                    MMADDRESS_NODE.LeftChild.offset(),
                    MMADDRESS_NODE.RightChild.offset(),
                    MMADDRESS_NODE.Parent.offset(),
                )
            }
            Some(OffsetsExt::V2(offsets)) => {
                let RTL_BALANCED_NODE = &offsets._RTL_BALANCED_NODE;

                (
                    RTL_BALANCED_NODE.Left.offset(),
                    RTL_BALANCED_NODE.Right.offset(),
                    RTL_BALANCED_NODE.ParentValue.offset(),
                )
            }
            None => panic!("OffsetsExt not set"),
        };

        Self {
            vmi,
            current: None,
            root,
            offset_left,
            offset_right,
            offset_parent,
            initialized: false,
        }
    }

    /// Creates an empty tree node iterator.
    pub fn empty(vmi: VmiState<'a, Driver, WindowsOs<Driver>>) -> Self {
        Self {
            vmi,
            current: None,
            root: Va(0),
            offset_left: 0,
            offset_right: 0,
            offset_parent: 0,
            initialized: true,
        }
    }

    /// Returns the left child of a node.
    fn left_child(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(node + self.offset_left)
    }

    /// Returns the right child of a node.
    fn right_child(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(node + self.offset_right)
    }

    /// Returns the parent of a node.
    fn parent_node(&self, node: Va) -> Result<Va, VmiError> {
        let result = self.vmi.read_va_native(node + self.offset_parent)?;

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

    /// Finds the first node in the tree.
    ///
    /// Returns `None` if the tree is `NULL`.
    fn find_first(&self) -> Result<Option<Va>, VmiError> {
        let offsets = &self.vmi.underlying_os().offsets;

        if self.root.is_null() {
            return Ok(None);
        }

        let mut current = match &offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

                self.vmi
                    .read_va_native(self.root + MMADDRESS_NODE.RightChild.offset())?
            }
            Some(OffsetsExt::V2(_)) => self.root,
            None => panic!("OffsetsExt not set"),
        };

        loop {
            let left = self.left_child(current)?;

            if left.is_null() {
                break;
            }

            current = left;
        }

        Ok(Some(current))
    }

    /// Walks to the next node in the tree.
    fn walk_next(&mut self) -> Result<Option<Va>, VmiError> {
        let result = match self.current {
            Some(current) => current,
            None => {
                // If `self.current` is `None`, we need to initialize the iterator.
                //
                // However, if the iterator has already been initialized, we should
                // return `None` to prevent infinite iteration.
                if self.initialized {
                    return Ok(None);
                }

                let first = match self.find_first()? {
                    Some(first) => first,
                    None => return Ok(None),
                };

                self.current = Some(first);
                self.initialized = true;
                first
            }
        };

        let mut current = result;
        let right = self.right_child(current)?;

        if !right.is_null() {
            current = right;

            loop {
                let left = self.left_child(current)?;

                if left.is_null() {
                    self.current = Some(current);
                    break;
                }

                current = left;
            }
        }
        else {
            loop {
                let parent = self.parent_node(current)?;

                if parent.is_null() || parent == current {
                    self.current = None;
                    break;
                }

                let left = self.left_child(parent)?;

                if left == current {
                    self.current = Some(parent);
                    break;
                }

                current = parent;
            }
        }

        Ok(Some(result))
    }
}

impl<Driver> Iterator for TreeNodeIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk_next().transpose()
    }
}

impl<Driver> FusedIterator for TreeNodeIterator<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
