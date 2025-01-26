use super::OsRegionKind;
use crate::{MemoryAccess, Va, VmiError};

/// Represents information about a process in the target system.
pub trait VmiOsRegion {
    /// Returns the virtual address of the region object.
    fn va(&self) -> Va;

    /// The start address of the region.
    fn start(&self) -> Result<Va, VmiError>;

    /// The end address of the region.
    fn end(&self) -> Result<Va, VmiError>;

    /// The protection flags of the region.
    fn protection(&self) -> Result<MemoryAccess, VmiError>;

    /// The kind of memory region.
    fn kind(&self) -> Result<OsRegionKind, VmiError>;
}
