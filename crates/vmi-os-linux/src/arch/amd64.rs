use vmi_arch_amd64::{Amd64, Registers};
use vmi_core::{
    Architecture as _, Pa, Va, VmiCore, VmiError, VmiSession, VmiState, driver::VmiRead, os::NoOS,
};

use super::ArchAdapter;
use crate::{LinuxError, LinuxKernelInformation, LinuxOs, offset, symbol};

/// Start of the kernel banner.
const BANNER_PREFIX: &[u8] = b"Linux version ";

/// Returns the release that a banner names, such as `7.0.0-38-generic`.
fn banner_release(banner: &str) -> &str {
    banner
        .get(BANNER_PREFIX.len()..)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default()
}

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiRead<Architecture = Self>,
{
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<LinuxKernelInformation>, VmiError> {
        /// Maximum forward search distance for the banner.
        ///
        /// On Ubuntu's 7.0.0-38, `linux_banner` lies 25.8 MiB after
        /// `entry_SYSCALL_64`.
        const MAX_FORWARD_SEARCH: u64 = 64 * 1024 * 1024;

        /// Distance after the first banner within which a later banner of the
        /// same release replaces it.
        ///
        /// Since Linux 6.1, `init/version.c` holds a weak `linux_banner`
        /// without the build time. The image keeps it, although the kernel
        /// uses the one in `init/version-timestamp.c`, which comes later. On
        /// Ubuntu's 7.0.0-38, the two lie 1.8 MiB apart.
        const MAX_COPY_DISTANCE: u64 = 16 * 1024 * 1024;

        /// Alignment of the search start, the size of a large page.
        const SEARCH_ALIGNMENT: u64 = 2 * 1024 * 1024;

        /// Maximum length of the banner.
        const MAX_BANNER_LENGTH: usize = 1024;

        const PAGE_SIZE: usize = Amd64::PAGE_SIZE as usize;

        let session = VmiSession::new(vmi, const { &NoOS(std::marker::PhantomData) });
        let vmi = session.with_registers(registers);

        let start = registers.msr_lstar & !(SEARCH_ALIGNMENT - 1);
        let mut end = start + MAX_FORWARD_SEARCH;
        let mut found: Option<String> = None;

        // The window holds the end of the previous page, then the current
        // page. A prefix across a page boundary is thus found as well.
        let overlap = BANNER_PREFIX.len();
        let mut window = vec![0u8; overlap + PAGE_SIZE];
        let mut previous_read = false;

        for page in (start..start + MAX_FORWARD_SEARCH).step_by(PAGE_SIZE) {
            if page >= end {
                break;
            }

            window.copy_within(PAGE_SIZE.., 0);

            match vmi.read(Va(page), &mut window[overlap..]) {
                Ok(()) => {}
                Err(VmiError::Translation(_)) => {
                    previous_read = false;
                    continue;
                }
                Err(err) => return Err(err),
            }

            let from = if previous_read { 0 } else { overlap };
            previous_read = true;

            for position in memchr::memmem::find_iter(&window[from..], BANNER_PREFIX) {
                let address = Va(page - overlap as u64 + (from + position) as u64);

                let banner = match vmi.read_string_limited(address, MAX_BANNER_LENGTH) {
                    Ok(banner) => banner,
                    Err(VmiError::Translation(_)) => continue,
                    Err(err) => return Err(err),
                };

                if !banner
                    .as_bytes()
                    .get(BANNER_PREFIX.len())
                    .is_some_and(u8::is_ascii_digit)
                {
                    continue;
                }

                match &found {
                    Some(first) if banner_release(first) != banner_release(&banner) => continue,
                    Some(_) => {}
                    None => end = end.min(address.0 + MAX_COPY_DISTANCE),
                }

                tracing::debug!(%address, "found kernel banner");
                found = Some(banner);
            }
        }

        match found {
            Some(banner) => Ok(Some(LinuxKernelInformation {
                banner: banner.trim_end_matches('\n').to_owned(),
            })),
            None => {
                tracing::trace!(
                    "no kernel banner found within {} MB",
                    MAX_FORWARD_SEARCH / 1024 / 1024
                );

                Ok(None)
            }
        }
    }

    fn syscall_argument(vmi: VmiState<LinuxOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        // On the first instruction of `entry_SYSCALL_64`, the arguments are
        // still in the registers of the syscall ABI.
        if registers.rip == registers.msr_lstar {
            return match index {
                0 => Ok(registers.rdi),
                1 => Ok(registers.rsi),
                2 => Ok(registers.rdx),
                3 => Ok(registers.r10),
                4 => Ok(registers.r8),
                5 => Ok(registers.r9),
                _ => Err(VmiError::OutOfBounds),
            };
        }

        // In the prologue of `__x64_sys_*`, `RDI` points to the `pt_regs` that
        // the entry code saved.
        let PT_REGS = offset!(vmi, pt_regs);

        let field = match index {
            0 => &PT_REGS.di,
            1 => &PT_REGS.si,
            2 => &PT_REGS.dx,
            3 => &PT_REGS.r10,
            4 => &PT_REGS.r8,
            5 => &PT_REGS.r9,
            _ => return Err(VmiError::OutOfBounds),
        };

        vmi.read_u64(Va(registers.rdi) + field.offset())
    }

    fn function_argument(vmi: VmiState<LinuxOs<Driver>>, index: u64) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        if registers.cs.access.long_mode() {
            function_argument_x64(vmi, index)
        }
        else {
            function_argument_x86(vmi, index)
        }
    }

    fn function_return_value(vmi: VmiState<LinuxOs<Driver>>) -> Result<u64, VmiError> {
        Ok(vmi.registers().rax)
    }

    fn kaslr_offset(vmi: VmiState<LinuxOs<Driver>>) -> Result<u64, VmiError> {
        /// KASLR moves the kernel in steps of `CONFIG_PHYSICAL_ALIGN`, at
        /// least 2 MiB.
        const KASLR_ALIGNMENT: u64 = 2 * 1024 * 1024;

        vmi.underlying_os()
            .kaslr_offset
            .get_or_try_init(|| {
                let msr_lstar = vmi.registers().msr_lstar;

                // With FRED, the kernel does not write `MSR_LSTAR`.
                if msr_lstar == 0 {
                    return Err(LinuxError::UnsupportedKernel("MSR_LSTAR is not set").into());
                }

                let kaslr_offset = msr_lstar.wrapping_sub(symbol!(vmi, entry_SYSCALL_64));
                if kaslr_offset % KASLR_ALIGNMENT != 0 {
                    return Err(LinuxError::UnsupportedProfile(
                        "MSR_LSTAR does not point to entry_SYSCALL_64 of the profile",
                    )
                    .into());
                }

                Ok(kaslr_offset)
            })
            .copied()
    }

    fn per_cpu_base(vmi: VmiState<LinuxOs<Driver>>) -> Va {
        let registers = vmi.registers();

        // In user mode, `KERNEL_GS_BASE` holds the kernel value, which
        // `swapgs` swaps in on kernel entry. A kernel value is a negative
        // address.
        if registers.cs.selector.request_privilege_level() != 0
            || (registers.gs.base & (1 << 47)) == 0
        {
            registers.shadow_gs.into()
        }
        else {
            registers.gs.base.into()
        }
    }

    fn user_translation_root(root: Pa) -> Pa {
        Pa(root.0 + Amd64::PAGE_SIZE)
    }
}

/// Reads a function argument of 32-bit code, from 4-byte stack slots.
fn function_argument_x86<Driver>(
    vmi: VmiState<LinuxOs<Driver>>,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    let registers = vmi.registers();

    let index = index + 1;
    let stack = registers.rsp + index * size_of::<u32>() as u64;
    Ok(vmi.read_u32(stack.into())? as u64)
}

/// Reads a function argument of 64-bit code, by the System V calling
/// convention.
fn function_argument_x64<Driver>(
    vmi: VmiState<LinuxOs<Driver>>,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    let registers = vmi.registers();

    match index {
        0 => Ok(registers.rdi),
        1 => Ok(registers.rsi),
        2 => Ok(registers.rdx),
        3 => Ok(registers.rcx),
        4 => Ok(registers.r8),
        5 => Ok(registers.r9),
        _ => {
            // The return address is on the top of the stack, the seventh
            // argument right above it.
            let index = index - 6 + 1;
            let stack = registers.rsp + index * size_of::<u64>() as u64;
            vmi.read_u64(stack.into())
        }
    }
}
