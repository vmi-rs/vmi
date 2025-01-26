use super::{ThreadId, ThreadObject};
use crate::VmiError;

/// A thread object.
pub trait VmiOsThread {
    /// Returns the thread ID.
    fn id(&self) -> Result<ThreadId, VmiError>;

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError>;
}
