use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};

use super::WindowsFileObject;
use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs};

/// A Windows section object.
pub struct WindowsControlArea<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_CONTROL_AREA` structure.
    va: Va,
}

impl<Driver> From<WindowsControlArea<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsControlArea<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> WindowsControlArea<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows section object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the file object associated with the control area.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_CONTROL_AREA.FilePointer`.
    pub fn file_object(&self) -> Result<WindowsFileObject<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let EX_FAST_REF = &offsets._EX_FAST_REF;
        let CONTROL_AREA = &offsets._CONTROL_AREA;

        let file_pointer = self
            .vmi
            .read_va_native(self.va + CONTROL_AREA.FilePointer.offset)?;

        // The file pointer is in fact an `_EX_FAST_REF` structure,
        // where the low bits are used to store the reference count.
        debug_assert_eq!(EX_FAST_REF.RefCnt.offset, 0);
        debug_assert_eq!(EX_FAST_REF.RefCnt.bit_position, 0);
        let file_pointer = file_pointer & !((1 << EX_FAST_REF.RefCnt.bit_length) - 1);
        //let file_pointer = file_pointer & !0xf;

        Ok(WindowsFileObject::new(self.vmi, file_pointer))
    }
}
