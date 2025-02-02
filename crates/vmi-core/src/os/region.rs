use super::{VmiOs, VmiOsRegionKind};
use crate::{MemoryAccess, Va, VmiDriver, VmiError, VmiVa};

/// A trait for memory regions.
///
/// This trait provides an abstraction over memory regions within a guest OS.
pub trait VmiOsRegion<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// Returns the starting virtual address of the memory region.
    fn start(&self) -> Result<Va, VmiError>;

    /// Returns the ending virtual address of the memory region.
    fn end(&self) -> Result<Va, VmiError>;

    /// Returns the memory protection of the memory region.
    fn protection(&self) -> Result<MemoryAccess, VmiError>;

    /// Returns the memory region's kind.
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Driver, Self::Os>, VmiError>;
}
