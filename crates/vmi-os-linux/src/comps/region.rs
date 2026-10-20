use vmi_core::{
    MemoryAccess, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsRegion, VmiOsRegionKind},
};

use super::LinuxFile;
use crate::{ArchAdapter, LinuxOs, offset};

/// The region can be read (`VM_READ`).
const VM_READ: u64 = 0x1;

/// The region can be written (`VM_WRITE`).
const VM_WRITE: u64 = 0x2;

/// The region can be executed (`VM_EXEC`).
const VM_EXEC: u64 = 0x4;

/// Writes to the region reach the mapped file or other processes
/// (`VM_SHARED`).
const VM_SHARED: u64 = 0x8;

/// A Linux memory region.
///
/// A memory region is a contiguous range of a process's address space with
/// one protection and one backing, anonymous memory or a mapped file.
///
/// # Implementation Details
///
/// Corresponds to `vm_area_struct`.
pub struct LinuxRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `vm_area_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxRegion<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux memory region.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the flags of the region (`VM_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_flags`.
    pub fn flags(&self) -> Result<u64, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        self.vmi.read_field(self.va, &VM_AREA_STRUCT.vm_flags)
    }

    /// Returns the offset of the region in the mapped file, in pages.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_pgoff`.
    pub fn pgoff(&self) -> Result<u64, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        self.vmi.read_field(self.va, &VM_AREA_STRUCT.vm_pgoff)
    }

    /// Checks if the region is shared.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `VM_SHARED` in `vm_area_struct.vm_flags`.
    pub fn is_shared(&self) -> Result<bool, VmiError> {
        Ok(self.flags()? & VM_SHARED != 0)
    }

    /// Returns the mapped file.
    ///
    /// Anonymous regions have none.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_file`.
    pub fn file(&self) -> Result<Option<LinuxFile<'a, Driver>>, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        let file = self
            .vmi
            .read_va_native(self.va + VM_AREA_STRUCT.vm_file.offset())?;

        if file.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxFile::new(self.vmi, file)))
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for LinuxRegion<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the starting virtual address of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_start`.
    fn start(&self) -> Result<Va, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        Ok(Va(self
            .vmi
            .read_field(self.va, &VM_AREA_STRUCT.vm_start)?))
    }

    /// Returns the ending virtual address of the memory region.
    ///
    /// The end is exclusive.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_end`.
    fn end(&self) -> Result<Va, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        Ok(Va(self.vmi.read_field(self.va, &VM_AREA_STRUCT.vm_end)?))
    }

    /// Returns the memory protection of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `VM_READ`, `VM_WRITE` and `VM_EXEC` in
    /// `vm_area_struct.vm_flags`.
    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        let flags = self.flags()?;

        let mut result = MemoryAccess::default();
        if flags & VM_READ != 0 {
            result |= MemoryAccess::R;
        }
        if flags & VM_WRITE != 0 {
            result |= MemoryAccess::W;
        }
        if flags & VM_EXEC != 0 {
            result |= MemoryAccess::X;
        }

        Ok(result)
    }

    /// Returns the memory region's kind.
    ///
    /// # Implementation Details
    ///
    /// `Private` if `vm_area_struct.vm_file` is `NULL`, otherwise
    /// `MappedData` with the mapped file. Telling an executable image from
    /// data needs the ELF header, which is not supported yet.
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Self::Os>, VmiError> {
        match self.file()? {
            Some(file) => Ok(VmiOsRegionKind::MappedData(file)),
            None => Ok(VmiOsRegionKind::Private),
        }
    }
}
