use serde::{Deserialize, Serialize};

use super::VmiOs;
use crate::{Va, VmiDriver, VmiError, VmiVa};

/// A thread ID within a system.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ThreadId(pub u32);

impl From<u32> for ThreadId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ThreadId> for u32 {
    fn from(value: ThreadId) -> Self {
        value.0
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A thread object within a system.
///
/// Equivalent to `ETHREAD*` on Windows.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ThreadObject(pub Va);

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

impl From<Va> for ThreadObject {
    fn from(value: Va) -> Self {
        Self(value)
    }
}

impl From<ThreadObject> for Va {
    fn from(value: ThreadObject) -> Self {
        value.0
    }
}

impl std::fmt::Display for ThreadObject {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
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
    type Os: VmiOs<Driver>;

    /// Returns the thread ID.
    fn id(&self) -> Result<ThreadId, VmiError>;

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError>;
}
