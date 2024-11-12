use once_cell::unsync::OnceCell;
use vmi_core::{
    os::{VmiOsRegion, VmiOsRegionKind},
    Architecture, MemoryAccess, Va, VmiDriver, VmiError, VmiState, VmiVa,
};

use super::macros::impl_offsets;
use crate::{ArchAdapter, LinuxOs};

/// A Linux VM area struct.
///
/// A `vm_area_struct` is a structure that represents a memory region (Virtual
/// Memory Area, or VMA) in a process's address space.
///
/// # Implementation Details
///
/// Corresponds to `vm_area_struct`.
pub struct LinuxVmAreaStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, LinuxOs<Driver>>,

    /// The virtual address of the `vm_area_struct` structure.
    va: Va,

    /// Cached flags.
    flags: OnceCell<u64>,
}

impl<Driver> VmiVa for LinuxVmAreaStruct<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for LinuxVmAreaStruct<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let start = self.start();
        let end = self.end();
        let protection = self.protection();
        //let kind = self.kind();

        f.debug_struct("LinuxVmAreaStruct")
            .field("start", &start)
            .field("end", &end)
            .field("protection", &protection)
            //.field("kind", &kind)
            .finish()
    }
}

impl<'a, Driver> LinuxVmAreaStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new VM area struct.
    pub fn new(vmi: VmiState<'a, Driver, LinuxOs<Driver>>, vad: Va) -> Self {
        Self {
            vmi,
            va: vad,
            flags: OnceCell::new(),
        }
    }

    /// Returns the flags of the memory region.
    ///
    /// The flags are a bitmask that represent the memory region's permissions
    /// and other attributes.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_flags`.
    pub fn flags(&self) -> Result<u64, VmiError> {
        self.flags
            .get_or_try_init(|| {
                let offsets = self.offsets();
                let __vm_area_struct = &offsets.vm_area_struct;

                self.vmi.read_field(self.va, &__vm_area_struct.vm_flags)
            })
            .copied()
    }
}

impl<'a, Driver> VmiOsRegion<'a, Driver> for LinuxVmAreaStruct<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the starting virtual address of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_start`.
    fn start(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let __vm_area_struct = &offsets.vm_area_struct;

        self.vmi
            .read_va_native(self.va + __vm_area_struct.vm_start.offset())
    }

    /// Returns the ending virtual address of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `vm_area_struct.vm_end`.
    fn end(&self) -> Result<Va, VmiError> {
        let offsets = self.offsets();
        let __vm_area_struct = &offsets.vm_area_struct;

        self.vmi
            .read_va_native(self.va + __vm_area_struct.vm_end.offset())
    }

    /// Returns the memory protection of the memory region.
    ///
    /// # Implementation Details
    ///
    /// Calculated from `vm_area_struct.vm_flags` field.
    fn protection(&self) -> Result<MemoryAccess, VmiError> {
        const VM_READ: u64 = 0x00000001;
        const VM_WRITE: u64 = 0x00000002;
        const VM_EXEC: u64 = 0x00000004;
        //const VM_SHARED: u64 = 0x00000008;

        let flags = self.flags()?;
        let mut protection = MemoryAccess::default();
        if flags & VM_READ != 0 {
            protection |= MemoryAccess::R;
        }
        if flags & VM_WRITE != 0 {
            protection |= MemoryAccess::W;
        }
        if flags & VM_EXEC != 0 {
            protection |= MemoryAccess::X;
        }

        Ok(protection)
    }

    /// Returns the memory region's kind.
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Driver, Self::Os>, VmiError> {
        let offsets = self.offsets();
        let __vm_area_struct = &offsets.vm_area_struct;

        let file = self
            .vmi
            .read_va_native(self.va + __vm_area_struct.vm_file.offset())?;

        if file.is_null() {
            return Ok(VmiOsRegionKind::Private);
        }

        unimplemented!()
    }
}
