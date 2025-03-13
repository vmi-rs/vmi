use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{LinuxDEntry, LinuxVFSMount, macros::impl_offsets};
use crate::{ArchAdapter, LinuxError, LinuxOs};

/// A Linux path struct.
///
/// The struct `path` is a fundamental structure in the Linux kernel used to
/// represent a location in the filesystem.
///
/// # Implementation Details
///
/// Corresponds to `path`.
pub struct LinuxPath<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `path` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxPath<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxPath<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `path`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the directory entry (dentry) in the VFS (Virtual Filesystem).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `path->dentry`.
    pub fn dentry(&self) -> Result<LinuxDEntry<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __path = &offsets.path;

        let dentry = self.vmi.read_va_native(self.va + __path.dentry.offset())?;

        if dentry.is_null() {
            return Err(LinuxError::CorruptedStruct("path->dentry").into());
        }

        Ok(LinuxDEntry::new(self.vmi, dentry))
    }

    /// Returns the the mount point associated with the path.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `path->mnt`.
    pub fn mnt(&self) -> Result<LinuxVFSMount<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __path = &offsets.path;

        let mnt = self.vmi.read_va_native(self.va + __path.mnt.offset())?;

        if mnt.is_null() {
            return Err(LinuxError::CorruptedStruct("path->mnt").into());
        }

        Ok(LinuxVFSMount::new(self.vmi, mnt))
    }
}
