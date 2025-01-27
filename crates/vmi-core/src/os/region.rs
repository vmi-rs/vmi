use super::{OsRegionKind, VmiOs};
use crate::{MemoryAccess, Va, VmiDriver, VmiError};

/// Represents information about a process in the target system.
pub trait VmiOsRegion<'a, Driver>: Into<Va> + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// The start address of the region.
    fn start(&self) -> Result<Va, VmiError>;

    /// The end address of the region.
    fn end(&self) -> Result<Va, VmiError>;

    /// The protection flags of the region.
    fn protection(&self) -> Result<MemoryAccess, VmiError>;

    /// The kind of memory region.
    fn kind(&self) -> Result<OsRegionKind, VmiError>;
}
