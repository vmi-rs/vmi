use std::iter::FusedIterator;

use vmi_core::{Architecture, Va, VmiRead, VmiError, VmiState};

use crate::{arch::ArchAdapter, offsets::OffsetsExt, WindowsOs};

/// An iterator for traversing tree nodes.
///
/// Iterate over nodes in a tree-like structure, specifically `MMADDRESS_NODE`
/// (Windows 7) and `RTL_BALANCED_NODE` (Windows 8.1+).
pub struct TreeNodeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// Current node.
    current: Option<Va>,

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
}

impl<'a, Driver> TreeNodeIterator<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new tree node iterator.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, root: Va) -> Result<Self, VmiError> {
        let offsets = &vmi.underlying_os().offsets;

        let (mut current, offset_left, offset_right, offset_parent) = match &offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

                (
                    vmi.read_va_native(root + MMADDRESS_NODE.RightChild.offset())?,
                    MMADDRESS_NODE.LeftChild.offset(),
                    MMADDRESS_NODE.RightChild.offset(),
                    MMADDRESS_NODE.Parent.offset(),
                )
            }
            Some(OffsetsExt::V2(offsets)) => {
                let RTL_BALANCED_NODE = &offsets._RTL_BALANCED_NODE;

                (
                    root,
                    RTL_BALANCED_NODE.Left.offset(),
                    RTL_BALANCED_NODE.Right.offset(),
                    RTL_BALANCED_NODE.ParentValue.offset(),
                )
            }
            None => panic!("OffsetsExt not set"),
        };

        loop {
            let left = vmi.read_va_native(current + offset_left)?;

            if left.is_null() {
                break;
            }

            current = left;
        }

        Ok(Self {
            vmi,
            current: Some(current),
            offset_left,
            offset_right,
            offset_parent,
        })
    }

    fn left(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(node + self.offset_left)
    }

    fn right(&self, node: Va) -> Result<Va, VmiError> {
        self.vmi.read_va_native(node + self.offset_right)
    }

    fn parent(&self, node: Va) -> Result<Va, VmiError> {
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
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Item = Result<Va, VmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.__next().transpose()
    }
}

impl<Driver> FusedIterator for TreeNodeIterator<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
