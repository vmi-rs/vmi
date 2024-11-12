use super::VmiOs;
use crate::{VmiDriver, VmiError, VmiVa};

/// A trait for memory mapped regions.
///
/// This trait provides an abstraction over memory mapped regions.
pub trait VmiOsMapped<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// Returns the path to the file backing the region.
    ///
    /// If the mapping is not backed by a file, this method will return `None`.
    fn path(&self) -> Result<Option<String>, VmiError>;
}
