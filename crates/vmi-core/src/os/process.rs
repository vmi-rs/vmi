use serde::{Deserialize, Serialize};

use super::{VmiOsImageArchitecture, VmiOs};
use crate::{Pa, Va, VmiDriver, VmiError, VmiVa};

/// A process ID within a system.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ProcessId(pub u32);

impl From<u32> for ProcessId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ProcessId> for u32 {
    fn from(value: ProcessId) -> Self {
        value.0
    }
}

impl std::fmt::Display for ProcessId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A process object within a system.
///
/// Equivalent to `EPROCESS*` on Windows or `task_struct*` on Linux.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ProcessObject(pub Va);

impl ProcessObject {
    /// Checks if the process object is a null reference.
    pub fn is_null(&self) -> bool {
        self.0 .0 == 0
    }

    /// Converts the process object to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.0 .0
    }
}

impl From<Va> for ProcessObject {
    fn from(va: Va) -> Self {
        Self(va)
    }
}

impl From<ProcessObject> for Va {
    fn from(value: ProcessObject) -> Self {
        value.0
    }
}

impl std::fmt::Display for ProcessObject {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    fn architecture(&self) -> Result<VmiOsImageArchitecture, VmiError>;

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
