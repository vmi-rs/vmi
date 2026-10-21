use vmi_core::{
    MemoryAccess, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsRegion, VmiOsRegionKind},
};

use super::{LinuxFile, LinuxMmStruct};
use crate::{ArchAdapter, LinuxError, LinuxOs, offset};

/// The region can be read (`VM_READ`).
const VM_READ: u64 = 0x1;

/// The region can be written (`VM_WRITE`).
const VM_WRITE: u64 = 0x2;

/// The region can be executed (`VM_EXEC`).
const VM_EXEC: u64 = 0x4;

/// Writes to the region reach the mapped file or other processes
/// (`VM_SHARED`).
const VM_SHARED: u64 = 0x8;

/// Upper limit for the steps that a walk over one file's regions takes, more
/// than any image has segments.
const IMAGE_STEPS_MAX: usize = 64;

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
        let file = self.file_address()?;

        if file.is_null() {
            return Ok(None);
        }

        Ok(Some(LinuxFile::new(self.vmi, file)))
    }

    /// Returns the address of the mapped `struct file`, which is null for an
    /// anonymous region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_file`.
    fn file_address(&self) -> Result<Va, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        self.vmi
            .read_va_native(self.va + VM_AREA_STRUCT.vm_file.offset())
    }

    /// Returns the memory descriptor that the region belongs to.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_mm`.
    pub fn mm(&self) -> Result<LinuxMmStruct<'a, Driver>, VmiError> {
        let VM_AREA_STRUCT = offset!(self.vmi, vm_area_struct);

        let mm = self
            .vmi
            .read_va_native(self.va + VM_AREA_STRUCT.vm_mm.offset())?;

        if mm.is_null() {
            return Err(LinuxError::CorruptedStruct("vm_area_struct.vm_mm").into());
        }

        Ok(LinuxMmStruct::new(self.vmi, mm))
    }

    /// Returns the header region of the region's file. That region maps the
    /// file's page 0, and its start is the image base.
    ///
    /// The walk steps back over the regions of the same file, across holes,
    /// until one has page offset 0. Returns `None` for an anonymous region,
    /// or when another file's region or the bottom of the address space ends
    /// the walk first.
    pub fn header_region(&self) -> Result<Option<LinuxRegion<'a, Driver>>, VmiError> {
        let file = self.file_address()?;
        if file.is_null() {
            return Ok(None);
        }

        let mm = self.mm()?;
        let mut region = LinuxRegion::new(self.vmi, self.va);

        for _ in 0..IMAGE_STEPS_MAX {
            if region.pgoff()? == 0 {
                return Ok(Some(region));
            }

            let start = region.start()?;
            if start.is_null() {
                return Ok(None);
            }

            region = match mm.region_at_or_below(start - 1)? {
                Some(previous) if previous.file_address()? == file => previous,
                _ => return Ok(None),
            };
        }

        Ok(None)
    }

    /// Checks if the region belongs to an image.
    ///
    /// The region's file must be an image file: a file that the process maps
    /// from page offset 0 and also maps executable. The test walks back to
    /// the header region and forward over the regions of the same file. It
    /// reads no user memory.
    pub fn is_image(&self) -> Result<bool, VmiError> {
        let header = match self.header_region()? {
            Some(header) => header,
            None => return Ok(false),
        };

        let file = header.file_address()?;
        let mm = header.mm()?;
        let mut region = header;

        for _ in 0..IMAGE_STEPS_MAX {
            if region.flags()? & VM_EXEC != 0 {
                return Ok(true);
            }

            region = match mm.region_at_or_above(region.end()?)? {
                Some(next) if next.file_address()? == file => next,
                _ => return Ok(false),
            };
        }

        Ok(false)
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
    /// `Private` if `vm_area_struct.vm_file` is `NULL`. A region with a file
    /// is `MappedImage` when the file is an image file (see [`is_image`]),
    /// and `MappedData` otherwise.
    ///
    /// [`is_image`]: LinuxRegion::is_image
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Self::Os>, VmiError> {
        let file = match self.file()? {
            Some(file) => file,
            None => return Ok(VmiOsRegionKind::Private),
        };

        if self.is_image()? {
            Ok(VmiOsRegionKind::MappedImage(file))
        }
        else {
            Ok(VmiOsRegionKind::MappedData(file))
        }
    }
}
