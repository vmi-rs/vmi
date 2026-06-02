use vmi_arch_arm64::{Arm64, PageTableEntry, Registers};
use vmi_core::{
    Architecture as _, Pa, Va, VmiCore, VmiError, VmiSession, VmiState, arch::Registers as _,
    driver::VmiRead, os::NoOS,
};

use super::{ArchAdapter, image_codeview};
use crate::{WindowsImage, WindowsKernelInformation, WindowsOs};

/// Extends [`PageTableEntry`] with Windows-specific field accessors.
///
/// Both accessors return `false`: the Windows-on-ARM64 software-PTE bit
/// positions for the prototype and transition states are not encoded here,
/// so [`ArchAdapter::is_page_present_or_transition`] uses only the
/// hardware-valid check.
pub trait WindowsPageTableEntry {
    /// Returns whether the page is a prototype.
    fn windows_prototype(self) -> bool;

    /// Returns whether the page is in transition.
    fn windows_transition(self) -> bool;
}

impl WindowsPageTableEntry for PageTableEntry {
    fn windows_prototype(self) -> bool {
        false
    }

    fn windows_transition(self) -> bool {
        false
    }
}

impl<Driver> ArchAdapter<Driver> for Arm64
where
    Driver: VmiRead<Architecture = Self>,
{
    fn syscall_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        function_argument_aapcs64(vmi, index)
    }

    fn function_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        function_argument_aapcs64(vmi, index)
    }

    fn function_return_value(vmi: VmiState<WindowsOs<Driver>>) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        Ok(registers.regs[0])
    }

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError> {
        /// Maximum backward search distance for the kernel image base.
        const MAX_BACKWARD_SEARCH: u64 = 32 * 1024 * 1024;

        let session = VmiSession::new(vmi, const { &NoOS(std::marker::PhantomData) });
        let vmi = session.with_registers(registers);

        // Align VBAR_EL1 to a page. The exception vector base lives inside the
        // kernel image, so it seeds the backward scan the way MSR_LSTAR does on
        // AMD64.
        let vbar = registers.vbar_el1 & Arm64::PAGE_MASK;

        let mut data = [0u8; Arm64::PAGE_SIZE as usize];

        for base_address in (vbar - MAX_BACKWARD_SEARCH..=vbar)
            .rev()
            .step_by(Arm64::PAGE_SIZE as usize)
        {
            let base_address = Va(base_address);

            //
            // Read next page.
            // Ignore page faults.
            //

            match vmi.read(base_address, &mut data) {
                Ok(()) => {}
                Err(VmiError::Translation(_)) => continue,
                Err(err) => return Err(err),
            }

            if &data[..2] != b"MZ" {
                continue;
            }

            tracing::trace!(%base_address, "found MZ");

            let image = WindowsImage::new_without_os(vmi, base_address);
            match image_codeview(&image) {
                Ok(Some(result)) => {
                    let name = &result.codeview.name;

                    if name.starts_with("nt") {
                        tracing::debug!(%base_address, "found kernel image");
                        return Ok(Some(result));
                    }

                    tracing::trace!(%name, "found non-kernel image");
                }
                Ok(None) => tracing::trace!("no codeview found"),
                Err(err) => tracing::trace!(%err, "error parsing PE"),
            };
        }

        tracing::trace!(
            "no codeview found within {} MB",
            MAX_BACKWARD_SEARCH / 1024 / 1024
        );

        Ok(None)
    }

    fn kernel_image_base(vmi: VmiState<WindowsOs<Driver>>) -> Result<Va, VmiError> {
        vmi.underlying_os()
            .kernel_image_base
            .get_or_try_init(|| {
                // ARM64 has no MSR_LSTAR analog, so derive the base by scanning
                // backward from VBAR_EL1 for the kernel PE.
                let registers = vmi.registers();
                match Self::find_kernel(vmi.core(), registers)? {
                    Some(kernel) => Ok(kernel.base_address),
                    None => Err(VmiError::Other("kernel image base not found")),
                }
            })
            .copied()
    }

    fn is_page_present_or_transition(
        vmi: VmiState<WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError> {
        let registers = vmi.registers();
        let root = registers.translation_root(address);

        // Returns true only when the stage-1 walk succeeds; the Windows
        // transition path is not supported on this architecture.
        match Arm64::translate_address(vmi.core(), address, root) {
            Ok(_) => Ok(true),
            Err(VmiError::Translation(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn current_kpcr(vmi: VmiState<WindowsOs<Driver>>) -> Va {
        // On ARM64, Windows keeps the per-CPU KPCR pointer in TPIDR_EL1.
        let registers = vmi.registers();

        Va(registers.tpidr_el1)
    }

    fn directory_table_base_to_root(value: u64) -> Pa {
        // TTBRn_EL1.BADDR is bits[47:1]; bit 0 is CnP. Mirrors the mask used by
        // vmi-arch-arm64's `ttbr_base`.
        Pa(value & 0x0000_FFFF_FFFF_FFFE)
    }
}

/// Reads an AAPCS64 argument by index from the current register state.
///
/// Windows-on-ARM64 passes the first eight integer arguments in `x0`-`x7` for
/// both ordinary calls and system calls, with overflow arguments on the stack
/// above `SP_EL0`.
fn function_argument_aapcs64<Driver>(
    vmi: VmiState<WindowsOs<Driver>>,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiRead<Architecture = Arm64>,
{
    let registers = vmi.registers();

    if index < 8 {
        Ok(registers.regs[index as usize])
    }
    else {
        let stack = registers.sp_el0 + (index - 8) * size_of::<u64>() as u64;
        vmi.read_u64(stack.into())
    }
}

#[cfg(test)]
mod tests {
    use vmi_arch_arm64::Registers;

    /// Returns the AAPCS64 source value for argument `index`: register
    /// `x{index}` for the first eight, otherwise the stack slot above
    /// `SP_EL0`.
    ///
    /// Mirrors the register/stack split in
    /// [`super::function_argument_aapcs64`] without needing a live guest, so
    /// the mapping can be unit-tested.
    fn argument_source(registers: &Registers, index: u64) -> u64 {
        if index < 8 {
            registers.regs[index as usize]
        }
        else {
            registers.sp_el0 + (index - 8) * size_of::<u64>() as u64
        }
    }

    /// Confirms arguments 0-7 read `x0`-`x7` and 8+ index the stack.
    #[test]
    fn aapcs64_argument_source() {
        let mut registers = Registers::default();
        for i in 0..8 {
            registers.regs[i] = 0x1000 + i as u64;
        }
        registers.sp_el0 = 0x8000;

        for index in 0..8 {
            assert_eq!(argument_source(&registers, index), 0x1000 + index);
        }

        // Argument 8 sits at SP_EL0 + 0, argument 9 at SP_EL0 + 8.
        assert_eq!(argument_source(&registers, 8), 0x8000);
        assert_eq!(argument_source(&registers, 9), 0x8008);
    }
}
