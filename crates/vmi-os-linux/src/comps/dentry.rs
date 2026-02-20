use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{LinuxQStr, macros::impl_offsets};
use crate::{ArchAdapter, LinuxOs};

/// A Linux dentry struct.
///
/// A `dentry` is a directory entry in the Linux kernel. It represents a file
/// or directory in the filesystem.
///
/// # Implementation Details
///
/// Corresponds to `dentry`.
pub struct LinuxDEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `dentry` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxDEntry<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxDEntry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `dentry`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the name of the dentry.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dentry.d_name`.
    pub fn name(&self) -> Result<Option<String>, VmiError> {
        let offsets = self.offsets();
        let __dentry = &offsets.dentry;

        LinuxQStr::new(self.vmi, self.va + __dentry.d_name.offset()).name()
    }

    /// Returns the parent dentry.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dentry.d_parent`.
    pub fn parent(&self) -> Result<Option<LinuxDEntry<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let __dentry = &offsets.dentry;

        let parent = self
            .vmi
            .read_va_native(self.va + __dentry.d_parent.offset())?;

        if parent.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxDEntry::new(self.vmi, parent)))
    }
}
