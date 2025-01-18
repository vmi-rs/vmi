use super::{ProcessId, ProcessObject};
use crate::{Pa, VmiError};

/// Represents information about a process in the target system.
pub trait VmiOsProcess {
    /// The PID of the process.
    fn id(&self) -> Result<ProcessId, VmiError>;

    /// The process object.
    fn object(&self) -> Result<ProcessObject, VmiError>;

    /// The short name of the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS::ImageFileName` (limited to 16 characters).
    /// - **Linux**: `_task_struct::comm` (limited to 16 characters).
    fn name(&self) -> Result<String, VmiError>;

    /// The translation root of the process.
    fn translation_root(&self) -> Result<Pa, VmiError>;
}
