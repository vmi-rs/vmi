use super::VmiOs;
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

/// Specifies the kind of memory region.
pub enum VmiOsRegionKind<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
    Self: 'a,
{
    /// A private region of memory.
    ///
    /// Such regions are usually created by functions like `VirtualAlloc` on
    /// Windows.
    Private,

    /// A mapped region of memory. Might be backed by a file.
    ///
    /// Such regions are usually created by functions like `MapViewOfFile` on
    /// Windows.
    Mapped(Os::Mapped<'a>),
}
