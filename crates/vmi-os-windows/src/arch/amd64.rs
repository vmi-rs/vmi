use vmi_arch_amd64::{Amd64, PageTableEntry, PageTableLevel, Registers};
use vmi_core::{
    Architecture as _, Va, VmiCore, VmiDriver, VmiError, VmiSession, VmiState,
    os::{NoOS, VmiOsImage},
};

use super::ArchAdapter;
use crate::{WindowsImage, WindowsKernelInformation, WindowsOs};

/// An extension trait for [`PageTableEntry`] that provides access to
/// Windows-specific fields.
trait WindowsPageTableEntry {
    /// Returns whether the page is a prototype.
    fn windows_prototype(self) -> bool;

    /// Returns whether the page is in transition.
    fn windows_transition(self) -> bool;
}

impl WindowsPageTableEntry for PageTableEntry {
    fn windows_prototype(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    fn windows_transition(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }
}

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        index: u64,
    ) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        match index {
            0 => Ok(registers.r10),
            1 => Ok(registers.rdx),
            2 => Ok(registers.r8),
            3 => Ok(registers.r9),
            _ => {
                let index = index + 1;
                let stack = registers.rsp + index * size_of::<u64>() as u64;
                vmi.read_u64(stack.into())
            }
        }
    }

    fn function_argument(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        index: u64,
    ) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        if registers.cs.access.long_mode() {
            function_argument_x64(vmi, index)
        }
        else {
            function_argument_x86(vmi, index)
        }
    }

    fn function_return_value(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Result<u64, VmiError> {
        let registers = vmi.registers();

        Ok(registers.rax)
    }

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError> {
        /// Maximum backward search distance for the kernel image base.
        const MAX_BACKWARD_SEARCH: u64 = 32 * 1024 * 1024;

        let session = VmiSession::new(vmi, &NoOS);
        let vmi = session.with_registers(registers);

        // Align MSR_LSTAR to 4KB.
        let lstar = registers.msr_lstar & Amd64::PAGE_MASK;

        let mut data = [0u8; Amd64::PAGE_SIZE as usize];

        for base_address in (lstar - MAX_BACKWARD_SEARCH..=lstar)
            .rev()
            .step_by(Amd64::PAGE_SIZE as usize)
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

            tracing::debug!(%base_address, "found MZ");

            let image = WindowsImage::new_without_os(vmi, base_address);
            match image_codeview(&image) {
                Ok(Some(result)) => return Ok(Some(result)),
                Ok(None) => tracing::warn!("No codeview found"),
                Err(err) => tracing::warn!(%err, "Error parsing PE"),
            };
        }

        tracing::warn!(
            "No codeview found within {} MB",
            MAX_BACKWARD_SEARCH / 1024 / 1024
        );

        Ok(None)
    }

    fn kernel_image_base(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Result<Va, VmiError> {
        vmi.underlying_os()
            .kernel_image_base
            .get_or_try_init(|| {
                let KiSystemCall64 = vmi.underlying_os().symbols.KiSystemCall64;

                let registers = vmi.registers();
                Ok(Va(registers.msr_lstar - KiSystemCall64))
            })
            .copied()
    }

    fn is_page_present_or_transition(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError> {
        let registers = vmi.registers();

        let translation = Amd64::translation(vmi.core(), address, registers.cr3.into());
        if let Some(entry) = translation.entries().last() {
            if entry.level == PageTableLevel::Pt {
                if entry.entry.present() {
                    // The address is valid if the page is present.
                    return Ok(true);
                }
                else if entry.entry.windows_transition() && !entry.entry.windows_prototype() {
                    // The Transition bit being 1 indicates that the page is in a transitional
                    // state. This means the page is not currently in the process's working
                    // set, but it's still resident in physical memory.
                    //
                    // If the process tries to access this page, it can be quickly brought
                    // back into the working set without needing to read from disk. This is
                    // sometimes called a "soft page fault" or "transition fault".
                    //
                    // This state is part of Windows' memory management optimization.
                    // It allows the system to keep pages in memory that might be needed
                    // again soon, without consuming the working set quota of processes.
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn current_kpcr(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Va {
        let registers = vmi.registers();

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

/*

fn find_kernel_slow<Driver>(
    vmi: VmiState<Driver>,
) -> Result<Option<WindowsKernelInformation>, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    tracing::debug!("performing slow kernel search");

    let info = vmi.info()?;

    for gfn in 0..info.max_gfn.0 {
        let gfn = Gfn(gfn);

        let data = match vmi.read_page(gfn) {
            Ok(page) => page,
            Err(_) => continue,
        };

        if &data[..2] != b"MZ" {
            continue;
        }

        let image = WindowsImage::new_from_pa(vmi, Amd64::pa_from_gfn(gfn));
        let result = match image_codeview(&image) {
            Ok(Some(result)) => result,
            _ => continue,
        };

        if !result.codeview.path.starts_with("nt") {
            continue;
        }

        return Ok(Some(result));
    }

    Ok(None)
}

*/

fn image_codeview<Driver>(
    image: &WindowsImage<Driver>,
) -> Result<Option<WindowsKernelInformation>, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    let debug_directory = match image.debug_directory()? {
        Some(debug_directory) => debug_directory,
        None => return Ok(None),
    };

    let codeview = match debug_directory.codeview()? {
        Some(codeview) => codeview,
        None => return Ok(None),
    };

    let optional_header = image.nt_headers()?.optional_header();

    Ok(Some(WindowsKernelInformation {
        base_address: image.base_address(),
        version_major: optional_header.major_operating_system_version(),
        version_minor: optional_header.minor_operating_system_version(),
        codeview,
    }))
}

fn function_argument_x86<Driver>(
    vmi: VmiState<Driver, WindowsOs<Driver>>,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    let registers = vmi.registers();

    let index = index + 1;
    let stack = registers.rsp + index * size_of::<u32>() as u64;
    Ok(vmi.read_u32(stack.into())? as u64)
}

fn function_argument_x64<Driver>(
    vmi: VmiState<Driver, WindowsOs<Driver>>,
    index: u64,
) -> Result<u64, VmiError>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    let registers = vmi.registers();

    match index {
        0 => Ok(registers.rcx),
        1 => Ok(registers.rdx),
        2 => Ok(registers.r8),
        3 => Ok(registers.r9),
        _ => {
            let index = index + 1;
            let stack = registers.rsp + index * size_of::<u64>() as u64;
            vmi.read_u64(stack.into())
        }
    }
}
