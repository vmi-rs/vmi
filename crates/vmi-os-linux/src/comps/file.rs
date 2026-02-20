use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{macros::impl_offsets, path::LinuxPath};
use crate::{ArchAdapter, LinuxOs};

/// A Linux file struct.
///
/// A `file` is a representation of a file in the Linux kernel.
///
/// # Implementation Details
///
/// Corresponds to `file`.
pub struct LinuxFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `file` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxFile<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `file`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the path of the file.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `file.f_path`.
    pub fn path(&self) -> Result<LinuxPath<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __file = &offsets.file;

        Ok(LinuxPath::new(self.vmi, self.va + __file.f_path.offset()))
    }
}
