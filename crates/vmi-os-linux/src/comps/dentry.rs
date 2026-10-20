use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use crate::{ArchAdapter, LinuxOs, offset};

/// A Linux directory entry.
///
/// A directory entry gives a file its name within its parent directory.
///
/// # Implementation Details
///
/// Corresponds to `dentry`.
pub struct LinuxDentry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `dentry` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxDentry<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxDentry<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux directory entry.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the name of the entry.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dentry.d_name`, a `qstr` with the name and its length.
    pub fn name(&self) -> Result<String, VmiError> {
        let DENTRY = offset!(self.vmi, dentry);
        let QSTR = offset!(self.vmi, qstr);

        let d_name = self.va + DENTRY.d_name.offset();
        let len = self.vmi.read_u32(d_name + QSTR.len.offset())?;
        let name = self.vmi.read_va_native(d_name + QSTR.name.offset())?;

        self.vmi.read_string_limited(name, len as usize)
    }

    /// Returns the parent directory.
    ///
    /// The root of a file system is its own parent.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `dentry.d_parent`.
    pub fn parent(&self) -> Result<LinuxDentry<'a, Driver>, VmiError> {
        let DENTRY = offset!(self.vmi, dentry);

        let d_parent = self
            .vmi
            .read_va_native(self.va + DENTRY.d_parent.offset())?;

        Ok(LinuxDentry::new(self.vmi, d_parent))
    }
}
