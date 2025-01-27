use super::{ThreadId, ThreadObject, VmiOs};
use crate::{Va, VmiDriver, VmiError};

/// A thread object.
pub trait VmiOsThread<'a, Driver>: Into<Va> + 'a
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
