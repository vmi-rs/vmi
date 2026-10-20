use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsModule};

use crate::{ArchAdapter, LinuxError, LinuxOs, offset};

/// The module is still being loaded (`MODULE_STATE_UNFORMED`).
const MODULE_STATE_UNFORMED: u32 = 3;

/// Index of the memory area with the module's code in `module.mem`
/// (`MOD_TEXT`).
const MOD_TEXT: u64 = 0;

/// A Linux kernel module.
///
/// A module is code and data that the kernel loads at runtime, such as a
/// driver.
///
/// # Implementation Details
///
/// Corresponds to `module`.
pub struct LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `module` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxModule<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux kernel module.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the state of the module (`MODULE_STATE_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.state`.
    pub fn state(&self) -> Result<u32, VmiError> {
        let MODULE = offset!(self.vmi, module);

        self.vmi.read_u32(self.va + MODULE.state.offset())
    }

    /// Checks if the module is still being loaded.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `MODULE_STATE_UNFORMED` in `module.state`.
    pub fn is_unformed(&self) -> Result<bool, VmiError> {
        Ok(self.state()? == MODULE_STATE_UNFORMED)
    }

    /// Returns the number of memory areas and the size of one.
    ///
    /// The kernel declares `module.mem` as an array of `MOD_MEM_NUM_TYPES`
    /// entries, a count that the profile gives only through the sizes.
    fn memory_layout(&self) -> Result<(u64, u64), VmiError> {
        let MODULE = offset!(self.vmi, module);
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let stride = MODULE_MEMORY.len() as u64;
        if stride == 0 {
            return Err(LinuxError::UnsupportedProfile("module_memory has no size").into());
        }

        Ok((MODULE.mem.size() / stride, stride))
    }

    /// Returns the address of a memory area of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.mem[index]`.
    fn memory(&self, index: u64) -> Result<Va, VmiError> {
        let MODULE = offset!(self.vmi, module);

        let (count, stride) = self.memory_layout()?;
        if index >= count {
            return Err(VmiError::OutOfBounds);
        }

        Ok(self.va + MODULE.mem.offset() + index * stride)
    }
}

impl<'a, Driver> VmiOsModule<'a, Driver> for LinuxModule<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the base address of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.mem[MOD_TEXT].base`.
    fn base_address(&self) -> Result<Va, VmiError> {
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let text = self.memory(MOD_TEXT)?;
        self.vmi.read_va_native(text + MODULE_MEMORY.base.offset())
    }

    /// Returns the size of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the sum of `module.mem[].size`, as
    /// `module_total_size` computes it for `/proc/modules`.
    fn size(&self) -> Result<u64, VmiError> {
        let MODULE_MEMORY = offset!(self.vmi, module_memory);

        let (count, _stride) = self.memory_layout()?;

        let mut size = 0;
        for index in 0..count {
            let memory = self.memory(index)?;
            size += self.vmi.read_u32(memory + MODULE_MEMORY.size.offset())? as u64;
        }

        Ok(size)
    }

    /// Returns the name of the module.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `module.name`.
    fn name(&self) -> Result<String, VmiError> {
        let MODULE = offset!(self.vmi, module);

        self.vmi
            .read_string_limited(self.va + MODULE.name.offset(), MODULE.name.size() as usize)
    }
}
