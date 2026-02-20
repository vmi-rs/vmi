use once_cell::unsync::OnceCell;
use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::macros::impl_offsets;
use crate::{ArchAdapter, LinuxOs};

/// A Linux qstr struct.
///
/// The struct `qstr` (short for "quick string") is a structure used in the
/// Virtual Filesystem (VFS) layer of the Linux kernel. It is primarily used
/// to represent filenames and directory entry names efficiently.
///
/// # Implementation Details
///
/// Corresponds to `qstr`.
pub struct LinuxQStr<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `qstr` structure.
    va: Va,

    len: OnceCell<u32>,
}

impl<Driver> VmiVa for LinuxQStr<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxQStr<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `qstr`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            len: OnceCell::new(),
        }
    }

    /// Returns the filename or directory name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `qstr->name`.
    pub fn name(&self) -> Result<Option<String>, VmiError> {
        let offsets = self.offsets();
        let __qstr = &offsets.qstr;

        let name = self.vmi.read_va_native(self.va + __qstr.name.offset())?;

        if name.is_null() {
            return Ok(None);
        }

        Ok(Some(
            self.vmi.read_string_limited(name, self.len()? as usize)?,
        ))
    }

    /// Returns the length of the string.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `qstr.len`.
    pub fn len(&self) -> Result<u32, VmiError> {
        self.len
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let __qstr = &offsets.qstr;

                self.vmi.read_u32(self.va + __qstr.len.offset())
            })
            .copied()
    }

    /// Returns whether the string is empty.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `qstr.len == 0`.
    pub fn is_empty(&self) -> Result<bool, VmiError> {
        Ok(self.len()? == 0)
    }
}
