use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{LinuxFile, macros::impl_offsets};
use crate::{ArchAdapter, LinuxOs, MapleTree};

/// A Linux mm struct.
///
/// The `mm_struct` structure is responsible for memory management information
/// of a process. It is responsible for tracking virtual memory mappings,
/// memory regions, page tables, and other crucial memory-related data.
///
/// # Implementation Details
///
/// Corresponds to `mm_struct`.
pub struct LinuxMmStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `mm_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxMmStruct<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxMmStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new `mm_struct`.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the page global directory (PGD) of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.pgd`.
    pub fn pgd(&self) -> Result<u64, VmiError> {
        let offsets = self.offsets();
        let __mm_struct = &offsets.mm_struct;

        self.vmi.read_field(self.va, &__mm_struct.pgd)
    }

    /// Returns the executable file of the process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.exe_file`.
    pub fn exe_file(&self) -> Result<Option<LinuxFile<'a, Driver>>, VmiError> {
        let offsets = self.offsets();
        let __mm_struct = &offsets.mm_struct;

        let exe_file = self
            .vmi
            .read_va_native(self.va + __mm_struct.exe_file.offset())?;

        if exe_file.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxFile::new(self.vmi, exe_file)))
    }

    /// Returns the memory map of the process.
    ///
    /// This is a data structure for managing virtual memory areas (VMAs).
    /// It replaces the older mm->mmap (linked list of VMAs) for faster lookups.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mm_struct.mm_mt`.
    pub fn mm_mt(&self) -> Result<MapleTree<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let __mm_struct = &offsets.mm_struct;

        Ok(MapleTree::new(
            self.vmi,
            self.va + __mm_struct.mm_mt.offset(),
        ))
    }

    /// Returns the address of the `mm_mt` field.
    pub fn mm_mt_va(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let __mm_struct = &offsets.mm_struct;
        Ok(self.va + __mm_struct.mm_mt.offset())
    }
}
