use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsMapped};

use super::LinuxPath;
use crate::{ArchAdapter, LinuxOs, offset};

/// A Linux file.
///
/// An open file, as the kernel keeps it for a file descriptor or a mapping
/// of a file into memory.
///
/// # Implementation Details
///
/// Corresponds to `file`.
pub struct LinuxFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `file` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxFile<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux file.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the path of the file.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `file.f_path`.
    pub fn f_path(&self) -> LinuxPath<'a, Driver> {
        let FILE = offset!(self.vmi, file);

        LinuxPath::new(self.vmi, self.va + FILE.f_path.offset())
    }
}

impl<'a, Driver> VmiOsMapped<'a, Driver> for LinuxFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the absolute path of the mapped file.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to [`LinuxPath::absolute`] of `file.f_path`.
    fn path(&self) -> Result<Option<String>, VmiError> {
        Ok(Some(self.f_path().absolute()?))
    }
}
