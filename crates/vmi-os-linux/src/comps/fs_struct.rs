use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{macros::impl_offsets, path::LinuxPath};
use crate::{ArchAdapter, LinuxOs};

/// A Linux fs struct.
///
/// The `fs_struct` structure is responsible for tracking filesystem-related
/// information for a process. Each process in Linux has a reference to an
/// `fs_struct`, which is shared across threads within the same thread group
/// (i.e., threads in the same process share the same filesystem state).
///
/// # Implementation Details
///
/// Corresponds to `fs_struct`.
pub struct LinuxFsStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `fs_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxFsStruct<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxFsStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `fs_struct`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the root directory (`/`) of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `fs_struct.root`.
    pub fn root(&self) -> Result<LinuxPath<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __fs_struct = &offsets.fs_struct;

        Ok(LinuxPath::new(
            self.vmi,
            self.va + __fs_struct.root.offset(),
        ))
    }

    /// Returns the current working directory (CWD) of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `fs_struct.pwd`.
    pub fn pwd(&self) -> Result<LinuxPath<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __fs_struct = &offsets.fs_struct;

        Ok(LinuxPath::new(self.vmi, self.va + __fs_struct.pwd.offset()))
    }
}
