use vmi_arch_aarch64::{Aarch64, PageTableEntry, Registers, ttbr_to_pa};
use vmi_core::{
    Architecture as _, Pa, Va, VmiCore, VmiError, VmiSession, VmiState,
    driver::VmiRead,
    os::{NoOS, VmiOsImageArchitecture},
};

use super::ArchAdapter;
use crate::{WindowsImage, WindowsKernelInformation, WindowsOs};

/// An extension trait for [`PageTableEntry`] that provides access to
/// Windows-specific fields.
pub(crate) trait WindowsPageTableEntry {
    /// Returns whether the page is a prototype.
    fn windows_prototype(self) -> bool;

    /// Returns whether the page is in transition.
    fn windows_transition(self) -> bool;
}

impl WindowsPageTableEntry for PageTableEntry {
    fn windows_prototype(self) -> bool {
        // TODO: implement Windows ARM64 prototype PTE check
        false
    }

    fn windows_transition(self) -> bool {
        // TODO: implement Windows ARM64 transition PTE check
        false
    }
}

impl<Driver> ArchAdapter<Driver> for Aarch64
where
    Driver: VmiRead<Architecture = Self>,
{
    fn syscall_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        // AAPCS64: arguments in x0-x7, then stack
        match index {
            0..=7 => Ok(registers.x[index as usize]),
            _ => {
                let stack_index = index - 8;
                let stack = registers.sp + stack_index * size_of::<u64>() as u64;
                vmi.read_u64(stack.into())
            }
        }
    }

    fn function_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        // ARM64 uses the same register convention for both syscalls and function calls
        Self::syscall_argument(vmi, index)
    }

    fn function_return_value(vmi: VmiState<WindowsOs<Driver>>) -> Result<u64, VmiError> {
        let registers = vmi.registers();
        Ok(registers.x[0])
    }

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError> {
        /// Maximum backward search distance for the kernel image base.
        const MAX_BACKWARD_SEARCH: u64 = 32 * 1024 * 1024;

        let session = VmiSession::new(vmi, const { &NoOS(std::marker::PhantomData) });
        let vmi = session.with_registers(registers);

        // Align VBAR_EL1 to page boundary.
        let vbar = registers.vbar_el1 & Aarch64::PAGE_MASK;

        if vbar == 0 {
            tracing::warn!("vbar_el1 is 0 — register may not be populated");
            return Ok(None);
        }

        let mut data = [0u8; Aarch64::PAGE_SIZE as usize];

        for base_address in (vbar.saturating_sub(MAX_BACKWARD_SEARCH)..=vbar)
            .rev()
            .step_by(Aarch64::PAGE_SIZE as usize)
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
            match super::image_codeview(&image) {
                Ok(Some(result)) => {
                    let path = &result.codeview.path;

                    if path.starts_with("nt") {
                        tracing::debug!(%base_address, "found kernel image");
                        return Ok(Some(result));
                    }

                    tracing::trace!(%path, "found non-kernel image");
                }
                Ok(None) => tracing::trace!("No codeview found"),
                Err(err) => tracing::trace!(%err, "Error parsing PE"),
            };
        }

        tracing::trace!(
            "No codeview found within {} MB",
            MAX_BACKWARD_SEARCH / 1024 / 1024
        );

        Ok(None)
    }

    fn kernel_image_base(vmi: VmiState<WindowsOs<Driver>>) -> Result<Va, VmiError> {
        vmi.underlying_os()
            .kernel_image_base
            .get_or_try_init(|| {
                let KiArm64ExceptionVectors = vmi
                    .underlying_os()
                    .symbols
                    .KiArm64ExceptionVectors
                    .ok_or(VmiError::NotSupported)?;

                let registers = vmi.registers();
                Ok(Va(registers.vbar_el1 - KiArm64ExceptionVectors))
            })
            .copied()
    }

    fn is_page_present_or_transition(
        _vmi: VmiState<WindowsOs<Driver>>,
        _address: Va,
    ) -> Result<bool, VmiError> {
        // TODO: implement Windows ARM64 transition PTE check
        Ok(true)
    }

    fn current_kpcr(vmi: VmiState<WindowsOs<Driver>>) -> Va {
        let registers = vmi.registers();
        Va(registers.tpidr_el1)
    }

    fn translation_root_from_raw(value: u64) -> Pa {
        ttbr_to_pa(value)
    }

    fn native_image_architecture() -> VmiOsImageArchitecture {
        VmiOsImageArchitecture::Aarch64
    }
}
