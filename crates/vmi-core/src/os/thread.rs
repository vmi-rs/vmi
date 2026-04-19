use super::{VmiOs, impl_ops};
use crate::{Va, VmiDriver, VmiError, VmiVa};

impl_ops! {
    /// A thread ID within a system.
    ThreadId, u32
}

impl_ops! {
    /// A thread object within a system.
    ///
    /// Equivalent to `ETHREAD*` on Windows.
    ThreadObject, Va
}

impl VmiVa for ThreadObject {
    fn va(&self) -> Va {
        self.0
    }
}

impl ThreadObject {
    /// Checks if the thread object is a null reference.
    pub fn is_null(&self) -> bool {
        self.0.0 == 0
    }

    /// Converts the thread object to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.0.0
    }
}

/// A trait for thread objects.
///
/// This trait provides an abstraction over threads within a guest OS.
pub trait VmiOsThread<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver>;

    /// Returns the thread ID.
    fn id(&self) -> Result<ThreadId, VmiError>;

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError>;
}
