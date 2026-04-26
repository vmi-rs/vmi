use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::WindowsControlArea;
use crate::{ArchAdapter, WindowsOs, offset};

/// A Windows segment.
///
/// A segment describes the prototype PTEs and commit accounting that
/// back a section. One segment is shared by every control area mapping
/// the same underlying object.
///
/// # Implementation Details
///
/// Corresponds to `_SEGMENT`.
pub struct WindowsSegment<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_SEGMENT` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsSegment<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSegment<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows segment.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the control area that owns this segment.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SEGMENT.ControlArea`.
    pub fn control_area(&self) -> Result<WindowsControlArea<'a, Driver>, VmiError> {
        let SEGMENT = offset!(self.vmi, _SEGMENT);

        let control_area = self
            .vmi
            .read_va_native(self.va + SEGMENT.ControlArea.offset())?;

        Ok(WindowsControlArea::new(self.vmi, control_area))
    }

    /// Returns the number of prototype PTEs covering the segment.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SEGMENT.TotalNumberOfPtes`.
    pub fn total_number_of_ptes(&self) -> Result<u32, VmiError> {
        let SEGMENT = offset!(self.vmi, _SEGMENT);

        let total_number_of_ptes = self
            .vmi
            .read_u32(self.va + SEGMENT.TotalNumberOfPtes.offset())?;

        Ok(total_number_of_ptes)
    }

    /// Returns the number of pages currently committed against the segment.
    ///
    /// For pagefile-backed sections this is the value WinDbg's `!vad`
    /// reports as "shared commit".
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SEGMENT.NumberOfCommittedPages`.
    pub fn number_of_committed_pages(&self) -> Result<u64, VmiError> {
        let SEGMENT = offset!(self.vmi, _SEGMENT);

        let number_of_committed_pages = self
            .vmi
            .read_address(self.va + SEGMENT.NumberOfCommittedPages.offset())?;

        Ok(number_of_committed_pages)
    }

    /// Returns the size of the segment in bytes.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_SEGMENT.SizeOfSegment`.
    pub fn size_of_segment(&self) -> Result<u64, VmiError> {
        let SEGMENT = offset!(self.vmi, _SEGMENT);

        let size_of_segment = self
            .vmi
            .read_address(self.va + SEGMENT.SizeOfSegment.offset())?;

        Ok(size_of_segment)
    }
}
