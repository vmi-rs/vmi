use super::{OsArchitecture, ProcessId, ProcessObject, VmiOs};
use crate::{Pa, Va, VmiDriver, VmiError, VmiVa};

/// A trait for process objects.
///
/// This trait provides an abstraction over processes within a guest OS.
pub trait VmiOsProcess<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// Returns the process ID.
    fn id(&self) -> Result<ProcessId, VmiError>;

    /// Returns the process object.
    fn object(&self) -> Result<ProcessObject, VmiError>;

    /// Returns the name of the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS.ImageFileName` (limited to 16 characters).
    /// - **Linux**: `_task_struct.comm` (limited to 16 characters).
    fn name(&self) -> Result<String, VmiError>;

    /// Returns the parent process ID.
    fn parent_id(&self) -> Result<ProcessId, VmiError>;

    /// Returns the architecture of the process.
    fn architecture(&self) -> Result<OsArchitecture, VmiError>;

    /// Returns the process's page table translation root.
    fn translation_root(&self) -> Result<Pa, VmiError>;

    /// Returns the user-mode page table translation root.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`translation_root`](Self::translation_root).
    fn user_translation_root(&self) -> Result<Pa, VmiError>;

    /// Returns the base address of the process image.
    fn image_base(&self) -> Result<Va, VmiError>;

    /// Returns an iterator over the process's memory regions.
    fn regions(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs<Driver>>::Region<'a>, VmiError>>,
        VmiError,
    >;

    /// Finds the memory region containing the given address.
    fn find_region(
        &self,
        address: Va,
    ) -> Result<Option<<Self::Os as VmiOs<Driver>>::Region<'a>>, VmiError>;

    /// Returns an iterator over the threads in the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS.ThreadListHead`.
    fn threads(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<<Self::Os as VmiOs<Driver>>::Thread<'a>, VmiError>>,
        VmiError,
    >;

    /// Checks whether the given virtual address is valid in the process.
    ///
    /// This method checks if page-faulting on the address would result in
    /// a successful access.
    fn is_valid_address(&self, address: Va) -> Result<Option<bool>, VmiError>;
}
