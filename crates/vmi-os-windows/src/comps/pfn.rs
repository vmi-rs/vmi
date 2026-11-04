use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::WindowsPte;
use crate::{ArchAdapter, WindowsOs, offset};

/// A Windows PFN entry.
///
/// The memory manager describes each page frame of physical memory with a
/// PFN entry. The entries form the PFN database, an array that the page
/// frame number indexes.
///
/// # Implementation Details
///
/// Corresponds to `_MMPFN`.
pub struct WindowsPfn<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_MMPFN` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsPfn<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsPfn<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows PFN entry.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the original PTE of the page frame.
    ///
    /// The entry keeps the original contents of the PTE that points to the
    /// frame. That PTE can be a prototype PTE. The memory manager restores
    /// the PTE from these contents when the frame leaves memory. A frame of
    /// a mapped file keeps a subsection PTE here. A frame of private memory,
    /// or of a section that the paging file backs, keeps a software PTE.
    /// Both decode as a prototype PTE. For a frame of an image section, the
    /// protection is the one that the section gives the page.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPFN.OriginalPte`.
    pub fn original_pte(&self) -> Result<WindowsPte, VmiError> {
        let MMPFN = offset!(self.vmi, _MMPFN);

        let original_pte = self.vmi.read_field(self.va, &MMPFN.OriginalPte)?;
        Ok(WindowsOs::prototype_pte(self.vmi, original_pte))
    }
}
