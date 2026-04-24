use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsMapped};

use super::{macros::impl_offsets, object::WindowsFileObject};
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _};

/// A Windows control area.
///
/// A control area is a kernel structure that describes a mapped section
/// of memory, typically associated with file-backed or pagefile-backed sections.
/// It manages shared pages and tracks section usage.
///
/// # Implementation Details
///
/// Corresponds to `_CONTROL_AREA`.
pub struct WindowsControlArea<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_CONTROL_AREA` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsControlArea<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsControlArea<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows control area.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the file object associated with the control area.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CONTROL_AREA.FilePointer` (with reference count masked out).
    pub fn file_object(&self) -> Result<Option<WindowsFileObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let CONTROL_AREA = &offsets._CONTROL_AREA;

        let file_pointer = self
            .vmi
            .os()
            .read_fast_ref(self.va + CONTROL_AREA.FilePointer.offset())?;

        if file_pointer.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsFileObject::new(self.vmi, file_pointer)))
    }
}

impl<'a, Driver> VmiOsMapped<'a, Driver> for WindowsControlArea<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    fn path(&self) -> Result<Option<String>, VmiError> {
        match self.file_object()? {
            Some(file_object) => Ok(Some(file_object.filename()?)),
            None => Ok(None),
        }
    }
}
