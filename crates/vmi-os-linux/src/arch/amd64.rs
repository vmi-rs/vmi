use vmi_arch_amd64::{Amd64, Cr3, Registers};
use vmi_core::{
    Architecture as _, Pa, Registers as _, Va, VmiCore, VmiError, VmiSession, VmiState,
    driver::VmiRead, os::NoOS,
};

use super::ArchAdapter;
use crate::{LinuxError, LinuxKernelInformation, LinuxOs, offset, symbol};

/// Start of the kernel banner.
const BANNER_PREFIX: &[u8] = b"Linux version ";

/// Bit of CR3 that selects the user page tables under KPTI
/// (`PTI_USER_PGTABLE_BIT`).
///
/// Under KPTI, the kernel allocates the top-level page table of a process as
/// an 8 KiB pair. The kernel half comes first. The user half, 4 KiB later,
/// maps the user space and almost none of the kernel. Without KPTI, a root
/// can have the bit set on its own.
const PTI_USER_PGTABLE_BIT: u64 = 1 << 12;

/// Returns the release that a banner names, such as `7.0.0-38-generic`.
fn banner_release(banner: &str) -> &str {
    banner
        .get(BANNER_PREFIX.len()..)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default()
}

/// Scans the memory after `MSR_LSTAR` for the kernel banner, through the page
/// tables in the given registers.
fn find_banner<Driver>(
    vmi: &VmiCore<Driver>,
    registers: &Registers,
) -> Result<Option<String>, VmiError>
where
    Driver: VmiRead<Architecture = Amd64>,
{
    /// Maximum forward search distance for the banner.
    ///
    /// On Ubuntu's 7.0.0-38, `linux_banner` lies 25.8 MiB after
    /// `entry_SYSCALL_64`.
    const MAX_FORWARD_SEARCH: u64 = 64 * 1024 * 1024;

    /// Distance after the first banner within which a later banner of the
    /// same release replaces it.
    ///
    /// Since Linux 6.1, `init/version.c` holds a weak `linux_banner` without
    /// the build time. The image keeps it, although the kernel uses the one
    /// in `init/version-timestamp.c`, which comes later. On Ubuntu's 7.0.0-38,
    /// the two lie 1.8 MiB apart.
    const MAX_COPY_DISTANCE: u64 = 16 * 1024 * 1024;

    /// Alignment of the search start, 2 MiB like a large page.
    const SEARCH_ALIGNMENT: u64 = 2 * 1024 * 1024;

    /// Maximum length of the banner.
    const MAX_BANNER_LENGTH: usize = 1024;

    const PAGE_SIZE: usize = Amd64::PAGE_SIZE as usize;

    let session = VmiSession::new(vmi, const { &NoOS(std::marker::PhantomData) });
    let vmi = session.with_registers(registers);

    let start = registers.msr_lstar & !(SEARCH_ALIGNMENT - 1);
    let mut end = start + MAX_FORWARD_SEARCH;
    let mut found: Option<String> = None;

    // The window holds the end of the previous page, then the current page.
    // A prefix across a page boundary is thus found as well.
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

    if found.is_none() {
        tracing::trace!(
            root = %Pa::from(registers.cr3),
            "no kernel banner found within {} MB",
            MAX_FORWARD_SEARCH / 1024 / 1024
        );
    }

    Ok(found)
}

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiRead<Architecture = Self>,
{
    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<LinuxKernelInformation>, VmiError> {
        let banner = match find_banner(vmi, registers)? {
            Some(banner) => Some(banner),

            // Retry through the kernel page tables, at bit 12 cleared. Under
            // KPTI, a vCPU in user mode runs on the user page tables, which
            // map the entry code but not the banner.
            None if registers.cr3.0 & PTI_USER_PGTABLE_BIT != 0 => {
                let mut kernel_registers = *registers;
                kernel_registers.cr3 = Cr3(registers.cr3.0 & !PTI_USER_PGTABLE_BIT);
                find_banner(vmi, &kernel_registers)?
            }

            None => None,
        };

        Ok(banner.map(|banner| LinuxKernelInformation {
            banner: banner.trim_end_matches('\n').to_owned(),
        }))
    }

    fn is_kernel_address(va: Va) -> bool {
        va.0 & (1 << 63) != 0
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

    fn kpti_enabled(vmi: VmiState<LinuxOs<Driver>>) -> Result<bool, VmiError> {
        /// `X86_FEATURE_PTI`, the same at Linux 6.8 and 7.0.
        const X86_FEATURE_PTI: u64 = 7 * 32 + 11;

        let CPUINFO_X86 = offset!(vmi, cpuinfo_x86);

        let boot_cpu_data = LinuxOs::symbol_address(vmi, symbol!(vmi, boot_cpu_data))?;
        let address = boot_cpu_data
            + CPUINFO_X86.x86_capability.offset()
            + X86_FEATURE_PTI / 32 * size_of::<u32>() as u64;

        // The reads name their roots, because `translation_root` asks for
        // this result. In user mode under KPTI, the root in CR3 does not map
        // `boot_cpu_data`.
        let root = vmi.registers().translation_root(address);
        let word = match vmi.read_u32_in((address, root)) {
            Ok(word) => word,
            Err(VmiError::Translation(_)) if root.0 & PTI_USER_PGTABLE_BIT != 0 => {
                vmi.read_u32_in((address, Pa(root.0 & !PTI_USER_PGTABLE_BIT)))?
            }
            Err(err) => return Err(err),
        };

        Ok(word & (1 << (X86_FEATURE_PTI % 32)) != 0)
    }

    fn thread_pointer(vmi: VmiState<LinuxOs<Driver>>) -> Va {
        Va(vmi.registers().fs.base)
    }

    fn translation_root(vmi: VmiState<LinuxOs<Driver>>, va: Va) -> Pa {
        let root = vmi.registers().translation_root(va);

        // Only a root with the user bit can be the user half of a KPTI pair.
        if root.0 & PTI_USER_PGTABLE_BIT == 0 {
            return root;
        }

        // Under KPTI, every address goes through the kernel half instead. It
        // maps the user space to the same frames, and the process reports it
        // as its root. Without KPTI, the bit belongs to an ordinary root. When
        // the check fails, the root in CR3 is the best guess left, since this
        // function cannot fail.
        if vmi.os().kpti_enabled().unwrap_or(false) {
            return Pa(root.0 & !PTI_USER_PGTABLE_BIT);
        }

        root
    }

    fn user_translation_root(root: Pa) -> Pa {
        Pa(root.0 | PTI_USER_PGTABLE_BIT)
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
