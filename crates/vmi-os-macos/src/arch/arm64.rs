use vmi_arch_arm64::{Arm64, Granule16KVa47, Registers};
use vmi_core::{
    Architecture as _, Registers as _, Va, VmiCore, VmiError, VmiState, driver::VmiRead,
};

use super::{ArchAdapter, kernel_information};
use crate::{MacOs, MacOsKernelInformation, macho::MH_MAGIC_64};

/// Number of arguments passed in registers by AAPCS64.
const REGISTER_ARGUMENTS: u64 = 8;

impl<Driver> ArchAdapter<Driver> for Arm64<Granule16KVa47>
where
    Driver: VmiRead<Architecture = Self>,
{
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers<Granule16KVa47>,
    ) -> Result<Option<MacOsKernelInformation>, VmiError> {
        /// Maximum backward search distance for the kernel collection header.
        const MAX_BACKWARD_SEARCH: u64 = 256 * 1024 * 1024;

        // The exception vectors live in the `__TEXT_EXEC` segment of the
        // kernel, which follows the header of the kernel collection.
        let vbar = Va(registers.vbar_el1);
        let root = registers.translation_root(vbar);

        let end = Self::va_align_down(vbar).0;
        let start = end.saturating_sub(MAX_BACKWARD_SEARCH);

        for address in (start..=end).rev().step_by(Self::PAGE_SIZE as usize) {
            let address = Va(address);

            // Skip pages that are not mapped or not present in memory.
            let magic = match vmi.read_u32((address, root)) {
                Ok(magic) => magic,
                Err(VmiError::Translation(_) | VmiError::OutOfBounds) => continue,
                Err(err) => return Err(err),
            };

            if magic != MH_MAGIC_64 {
                continue;
            }

            // Headers of other images, or data that merely starts with the
            // magic, are skipped.
            match kernel_information(vmi, address, root) {
                Ok(Some(result)) => return Ok(Some(result)),
                Ok(None) => continue,
                Err(VmiError::Translation(_) | VmiError::OutOfBounds | VmiError::Os(_)) => continue,
                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }

    fn canonical_address(raw: u64) -> Va {
        Self::canonical_address(raw)
    }

    fn current_thread(vmi: VmiState<MacOs<Driver>>) -> Va {
        Self::canonical_address(vmi.registers().tpidr_el1)
    }

    fn syscall_argument(vmi: VmiState<MacOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        // Unix and Mach traps take their arguments in the same registers as
        // regular calls. `X16` holds the syscall number.
        Self::function_argument(vmi, index)
    }

    fn function_argument(vmi: VmiState<MacOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        if index < REGISTER_ARGUMENTS {
            return Ok(registers.regs[index as usize]);
        }

        let stack_pointer = Va(registers.stack_pointer());
        vmi.read_u64(stack_pointer + (index - REGISTER_ARGUMENTS) * 8)
    }

    fn function_return_value(vmi: VmiState<MacOs<Driver>>) -> Result<u64, VmiError> {
        Ok(vmi.registers().regs[0])
    }
}
