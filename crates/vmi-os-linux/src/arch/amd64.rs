use vmi_arch_amd64::{Amd64, Registers};
use vmi_core::{Architecture as _, Registers as _, Va, VmiCore, VmiDriver, VmiError};

use super::ArchAdapter;
use crate::LinuxOs;

#[allow(non_snake_case)]
impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        _os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &Registers,
        index: u64,
    ) -> Result<u64, VmiError> {
        match index {
            0 => Ok(registers.r10),
            1 => Ok(registers.rdx),
            2 => Ok(registers.r8),
            3 => Ok(registers.r9),
            _ => {
                let index = index + 1;
                let stack = registers.rsp + index * size_of::<u64>() as u64;
                vmi.read_u64(registers.address_context(stack.into()))
            }
        }
    }

    fn function_argument(
        _os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &Registers,
        index: u64,
    ) -> Result<u64, VmiError> {
        if registers.cs.access.long_mode() {
            function_argument_x64(vmi, registers, index)
        }
        else {
            function_argument_x86(vmi, registers, index)
        }
    }

    fn function_return_value(
        _os: &LinuxOs<Driver>,
        _vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<u64, VmiError> {
        Ok(registers.rax)
    }

    fn find_banner(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<String>, VmiError> {
        /// Maximum backward search distance for the kernel image base.
        const MAX_FORWARD_SEARCH: u64 = 16 * 1024 * 1024;
        const MAX_BACKWARD_SEARCH: u64 = 16 * 1024 * 1024;
        const LINUX_VERSION_SIGNATURE: &[u8] = b"Linux version";

        // Align MSR_LSTAR to 4KB.
        let lstar = registers.msr_lstar & Amd64::PAGE_MASK;
        let from_va = lstar - MAX_BACKWARD_SEARCH;
        let to_va = lstar + MAX_FORWARD_SEARCH;

        let mut data = [0u8; Amd64::PAGE_SIZE as usize];

        for va in (from_va..=to_va).rev().step_by(Amd64::PAGE_SIZE as usize) {
            let va = Va(va);

            //
            // Read next page.
            // Ignore page faults.
            //

            match vmi.read(registers.address_context(va), &mut data) {
                Ok(()) => {}
                Err(VmiError::PageFault(_)) => continue,
                Err(err) => return Err(err),
            }

            for index in memchr::memmem::find_iter(&data, LINUX_VERSION_SIGNATURE) {
                let banner_address = va + index as u64;
                tracing::debug!(%banner_address, "found banner");

                //
                // Beginning of the banner.
                //

                let banner = &data[index..];

                //
                // Banner ends with \n\0.
                //

                let banner = match memchr::memmem::find(banner, b"\n\0") {
                    Some(index) => &banner[..index],
                    None => continue,
                };

                return Ok(Some(String::from_utf8_lossy(banner).into()));
            }
        }

        tracing::warn!(
            "No banner found within {} MB",
            MAX_BACKWARD_SEARCH / 1024 / 1024
        );

        Ok(None)
    }

    fn kernel_image_base(
        os: &LinuxOs<Driver>,
        _vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Va, VmiError> {
        let entry_SYSCALL_64 = os.symbols.entry_SYSCALL_64;
        let _text = os.symbols._text;

        if let Some(kernel_image_base) = *os.kernel_image_base.borrow() {
            return Ok(kernel_image_base);
        }

        let kaslr_offset = registers.msr_lstar - entry_SYSCALL_64;
        *os.kaslr_offset.borrow_mut() = Some(kaslr_offset);

        let kernel_image_base = Va::new(_text + kaslr_offset);
        *os.kernel_image_base.borrow_mut() = Some(kernel_image_base);
        Ok(kernel_image_base)
    }

    fn kaslr_offset(
        os: &LinuxOs<Driver>,
        _vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<u64, VmiError> {
        let entry_SYSCALL_64 = os.symbols.entry_SYSCALL_64;

        if let Some(kaslr_offset) = *os.kaslr_offset.borrow() {
            return Ok(kaslr_offset);
        }

        let kaslr_offset = registers.msr_lstar - entry_SYSCALL_64;
        *os.kaslr_offset.borrow_mut() = Some(kaslr_offset);
        Ok(kaslr_offset)
    }

    fn per_cpu(_os: &LinuxOs<Driver>, _vmi: &VmiCore<Driver>, registers: &Registers) -> Va {
        if registers.cs.selector.request_privilege_level() != 0
            || (registers.gs.base & (1 << 47)) == 0
        {
            registers.shadow_gs.into()
        }
        else {
            registers.gs.base.into()
        }
    }
}

fn function_argument_x86<Driver>(
    vmi: &VmiCore<Driver>,
    registers: &Registers,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    let index = index + 1;
    let stack = registers.rsp + index * size_of::<u32>() as u64;
    Ok(vmi.read_u32(registers.address_context(stack.into()))? as u64)
}

fn function_argument_x64<Driver>(
    vmi: &VmiCore<Driver>,
    registers: &Registers,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    match index {
        0 => Ok(registers.rdi),
        1 => Ok(registers.rsi),
        2 => Ok(registers.rdx),
        3 => Ok(registers.rcx),
        4 => Ok(registers.r8),
        5 => Ok(registers.r9),
        _ => {
            let index = index - 6 + 1;
            let stack = registers.rsp + index * size_of::<u64>() as u64;
            vmi.read_u64(registers.address_context(stack.into()))
        }
    }
}
