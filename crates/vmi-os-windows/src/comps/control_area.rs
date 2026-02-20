use vmi_core::{Architecture, Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsMapped};

use super::{macros::impl_offsets, object::WindowsFileObject};
use crate::{ArchAdapter, WindowsOs};

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
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_CONTROL_AREA` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsControlArea<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsControlArea<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows control area.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the file object associated with the control area.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CONTROL_AREA.FilePointer` (with reference count masked out).
    pub fn file_object(&self) -> Result<Option<WindowsFileObject<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let EX_FAST_REF = &offsets._EX_FAST_REF;
        let CONTROL_AREA = &offsets._CONTROL_AREA;

        let file_pointer = self
            .vmi
            .read_va_native(self.va + CONTROL_AREA.FilePointer.offset())?;

        // The file pointer is in fact an `_EX_FAST_REF` structure,
        // where the low bits are used to store the reference count.
        debug_assert_eq!(EX_FAST_REF.RefCnt.offset(), 0);
        debug_assert_eq!(EX_FAST_REF.RefCnt.bit_position(), 0);
        let file_pointer = file_pointer & !((1 << EX_FAST_REF.RefCnt.bit_length()) - 1);
        //let file_pointer = file_pointer & !0xf;

        if file_pointer.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsFileObject::new(self.vmi, file_pointer)))
    }
}

impl<'a, Driver> VmiOsMapped<'a, Driver> for WindowsControlArea<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    fn path(&self) -> Result<Option<String>, VmiError> {
        match self.file_object()? {
            Some(file_object) => Ok(Some(file_object.filename()?)),
            None => Ok(None),
        }
    }
}
