use super::{OsArchitecture, ProcessId, ProcessObject, VmiOsRegion};
use crate::{Pa, Va, VmiError};

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

    /// Retrieves the parent process ID for a given process object.
    fn parent_id(&self) -> Result<ProcessId, VmiError>;

    /// Retrieves the architecture of a given process.
    fn architecture(&self) -> Result<OsArchitecture, VmiError>;

    /// Retrieves the translation root for a given process.
    fn translation_root(&self) -> Result<Pa, VmiError>;

    /// Retrieves the base address of the user translation root for a given
    /// process.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`VmiOs::process_translation_root`].
    fn user_translation_root(&self) -> Result<Pa, VmiError>;

    /// Retrieves the base address of the process image.
    fn image_base(&self) -> Result<Va, VmiError>;

    /// Retrieves a list of memory regions for a given process.
    fn regions(&self)
        -> Result<impl Iterator<Item = Result<impl VmiOsRegion, VmiError>>, VmiError>;

    /// Checks if a given virtual address is valid in a given process.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError>;
}
