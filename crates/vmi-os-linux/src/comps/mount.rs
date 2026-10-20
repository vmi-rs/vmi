use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::LinuxDentry;
use crate::{ArchAdapter, LinuxOs, offset};

/// A Linux mount.
///
/// A mount attaches a file system to a directory entry of its parent mount,
/// the mount point.
///
/// # Implementation Details
///
/// Corresponds to `mount`.
pub struct LinuxMount<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `mount` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxMount<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxMount<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux mount.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the parent mount.
    ///
    /// The root mount of a mount namespace is its own parent.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mount.mnt_parent`.
    pub fn parent(&self) -> Result<LinuxMount<'a, Driver>, VmiError> {
        let MOUNT = offset!(self.vmi, mount);

        let mnt_parent = self
            .vmi
            .read_va_native(self.va + MOUNT.mnt_parent.offset())?;

        Ok(LinuxMount::new(self.vmi, mnt_parent))
    }

    /// Returns the mount point, a directory entry of the parent mount.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mount.mnt_mountpoint`.
    pub fn mountpoint(&self) -> Result<LinuxDentry<'a, Driver>, VmiError> {
        let MOUNT = offset!(self.vmi, mount);

        let mnt_mountpoint = self
            .vmi
            .read_va_native(self.va + MOUNT.mnt_mountpoint.offset())?;

        Ok(LinuxDentry::new(self.vmi, mnt_mountpoint))
    }

    /// Returns the part of the mount that the rest of the kernel sees.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mount.mnt`.
    pub fn vfsmount(&self) -> LinuxVfsMount<'a, Driver> {
        let MOUNT = offset!(self.vmi, mount);

        LinuxVfsMount::new(self.vmi, self.va + MOUNT.mnt.offset())
    }
}

/// The part of a Linux mount that the rest of the kernel sees.
///
/// # Implementation Details
///
/// Corresponds to `vfsmount`, which `mount` embeds as `mount.mnt`.
pub struct LinuxVfsMount<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `vfsmount` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxVfsMount<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxVfsMount<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux `vfsmount`.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the root directory entry of the mounted file system.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vfsmount.mnt_root`.
    pub fn root(&self) -> Result<LinuxDentry<'a, Driver>, VmiError> {
        let VFSMOUNT = offset!(self.vmi, vfsmount);

        let mnt_root = self
            .vmi
            .read_va_native(self.va + VFSMOUNT.mnt_root.offset())?;

        Ok(LinuxDentry::new(self.vmi, mnt_root))
    }

    /// Returns the mount that embeds this structure.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `real_mount`, which subtracts the offset of
    /// `mount.mnt`.
    pub fn mount(&self) -> LinuxMount<'a, Driver> {
        let MOUNT = offset!(self.vmi, mount);

        LinuxMount::new(self.vmi, self.va - MOUNT.mnt.offset())
    }
}
