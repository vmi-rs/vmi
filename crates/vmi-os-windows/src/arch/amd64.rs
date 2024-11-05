use object::{FileKind, LittleEndian as LE};
use vmi_arch_amd64::{Amd64, PageTableEntry, PageTableLevel, Registers};
use vmi_core::{
    os::ProcessObject, Architecture as _, Registers as _, Va, VmiCore, VmiDriver, VmiError,
};

use super::ArchAdapter;
use crate::{
    pe::codeview::codeview_from_pe, PeLite32, PeLite64, WindowsKernelInformation, WindowsOs,
};

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
        self.0 >> 10 & 1 != 0
    }

    fn windows_transition(self) -> bool {
        self.0 >> 11 & 1 != 0
    }
}

impl<Driver> ArchAdapter<Driver> for Amd64
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        _os: &WindowsOs<Driver>,
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
        _os: &WindowsOs<Driver>,
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
        _os: &WindowsOs<Driver>,
        _vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<u64, VmiError> {
        Ok(registers.rax)
    }

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError> {
        /// Maximum backward search distance for the kernel image base.
        const MAX_BACKWARD_SEARCH: u64 = 32 * 1024 * 1024;

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

            match vmi.read(registers.address_context(base_address), &mut data) {
                Ok(()) => {}
                Err(VmiError::PageFault(_)) => continue,
                Err(err) => return Err(err),
            }

            if &data[..2] != b"MZ" {
                continue;
            }

            tracing::debug!(%base_address, "found MZ");
            match FileKind::parse(&data[..]) {
                Ok(FileKind::Pe32) => {
                    let pe = PeLite32::parse(&data).map_err(|err| VmiError::Os(err.into()))?;
                    if let Some(codeview) =
                        codeview_from_pe(vmi, registers.address_context(base_address), &pe)?
                    {
                        let optional_header = &pe.nt_headers.optional_header;

                        return Ok(Some(WindowsKernelInformation {
                            base_address,
                            version_major: optional_header.major_operating_system_version.get(LE),
                            version_minor: optional_header.minor_operating_system_version.get(LE),
                            codeview,
                        }));
                    }
                    else {
                        tracing::warn!("No codeview found");
                    }
                }
                Ok(FileKind::Pe64) => {
                    let pe = PeLite64::parse(&data).map_err(|err| VmiError::Os(err.into()))?;
                    if let Some(codeview) =
                        codeview_from_pe(vmi, registers.address_context(base_address), &pe)?
                    {
                        let optional_header = &pe.nt_headers.optional_header;

                        return Ok(Some(WindowsKernelInformation {
                            base_address,
                            version_major: optional_header.major_operating_system_version.get(LE),
                            version_minor: optional_header.minor_operating_system_version.get(LE),
                            codeview,
                        }));
                    }
                    else {
                        tracing::warn!("No codeview found");
                    }
                }
                Ok(kind) => {
                    tracing::warn!(?kind, "Unsupported architecture");
                }
                Err(err) => {
                    tracing::warn!(%err, "Error parsing PE");
                }
            }
        }

        tracing::warn!(
            "No codeview found within {} MB",
            MAX_BACKWARD_SEARCH / 1024 / 1024
        );

        Ok(None)
    }

    fn kernel_image_base(
        os: &WindowsOs<Driver>,
        _vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Va, VmiError> {
        let KiSystemCall64 = os.symbols.KiSystemCall64;

        if let Some(kernel_image_base) = *os.kernel_image_base.borrow() {
            return Ok(kernel_image_base);
        }

        let kernel_image_base = Va::new(registers.msr_lstar - KiSystemCall64);
        *os.kernel_image_base.borrow_mut() = Some(kernel_image_base);
        Ok(kernel_image_base)
    }

    fn process_address_is_valid(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError> {
        //
        // So, the logic is roughly as follows:
        // - Translate the address and try to find the page table entry.
        //   - If the page table entry is found:
        //     - If the page is present, the address is valid.
        //     - If the page is in transition AND not a prototype, the address is valid.
        // - Find the VAD for the address.
        //   - If the VAD is not found, the address is invalid.
        // - If the VadType is VadImageMap, the address is valid.
        //   - If the VadType is not VadImageMap, we don't care (VadAwe, physical
        //     memory, ...).
        // - If the PrivateMemory bit is not set, the address is invalid.
        // - If the MemCommit bit is not set, the address is invalid.
        //
        // References:
        // - MmAccessFault
        // - MiDispatchFault
        // - MiQueryAddressState
        // - MiCheckVirtualAddress
        //

        let translation = Amd64::translation(vmi, address, registers.cr3.into());
        if let Some(entry) = translation.entries().last() {
            if entry.level == PageTableLevel::Pt {
                if entry.entry.present() {
                    // The address is valid if the page is present.
                    return Ok(Some(true));
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
                    return Ok(Some(true));
                }
            }
        }

        //
        // TODO: The code below should be moved to a separate architecture-independent
        // function.
        //

        let vad_va = match os.find_process_vad(vmi, registers, process, address)? {
            Some(vad_va) => vad_va,
            None => return Ok(Some(false)),
        };

        const MM_ZERO_ACCESS: u8 = 0; // this value is not used.
        const MM_DECOMMIT: u8 = 0x10; // NO_ACCESS, Guard page
        const MM_NOACCESS: u8 = 0x18; // NO_ACCESS, Guard_page, nocache.

        const VadImageMap: u8 = 2;

        let vad = os.vad(vmi, registers, vad_va)?;

        if matches!(vad.protection, MM_ZERO_ACCESS | MM_DECOMMIT | MM_NOACCESS) {
            return Ok(Some(false));
        }

        Ok(Some(
            // Private memory must be committed.
            (vad.private_memory && vad.mem_commit) ||

            // Non-private memory must be mapped from an image.
            // Note that this isn't actually correct, because
            // some parts of the image might not be committed,
            // or they can have different protection than the VAD.
            //
            // However, figuring out the correct protection would
            // be quite complex, so we just assume that the image
            // is always committed and has the same protection as
            // the VAD.
            (!vad.private_memory && vad.vad_type == VadImageMap),
        ))
    }

    fn current_kpcr(_os: &WindowsOs<Driver>, _vmi: &VmiCore<Driver>, registers: &Registers) -> Va {
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
        0 => Ok(registers.rcx),
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
