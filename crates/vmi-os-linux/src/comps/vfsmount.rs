use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{LinuxDEntry, macros::impl_offsets};
use crate::{ArchAdapter, LinuxError, LinuxOs};

/// A Linux VFS mount struct.
///
/// The `vfsmount` structure is used to represent a mounted filesystem instance
/// in the Linux Virtual Filesystem (VFS).
///
/// # Implementation Details
///
/// Corresponds to `vfsmount`.
pub struct LinuxVFSMount<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `vfsmount` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxVFSMount<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxVFSMount<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new VFS mount.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the root directory entry (`dentry`) of the mount.
    ///
    /// `mnt_root` points to the root directory (`/`) of the mounted filesystem.
    /// It is a `dentry` (directory entry) that represents the starting point of
    /// the filesystem. Every mount point has a `mnt_root`, but this root does
    /// not necessarily have to be `/` (e.g., for a chroot environment, the root
    /// could be `/home/user`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vfsmount->mnt_root`.
    pub fn mnt_root(&self) -> Result<LinuxDEntry<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __vfsmount = &offsets.vfsmount;

        let mnt_root = self
            .vmi
            .read_va_native(self.va + __vfsmount.mnt_root.offset())?;

        if mnt_root.is_null() {
            return Err(LinuxError::CorruptedStruct("vfsmount->mnt_root").into());
        }

        Ok(LinuxDEntry::new(self.vmi, mnt_root))
    }
}
