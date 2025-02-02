use super::{ThreadId, ThreadObject, VmiOs};
use crate::{VmiDriver, VmiError, VmiVa};

/// A trait for thread objects.
///
/// This trait provides an abstraction over threads within a guest OS.
pub trait VmiOsThread<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// Returns the thread ID.
    fn id(&self) -> Result<ThreadId, VmiError>;

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError>;
}
