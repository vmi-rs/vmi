//! VMI driver for QEMU ELF core dumps.
//!
//! Reads guest physical memory from the `PT_LOAD` segments of a core dump
//! created by the QEMU `dump-guest-memory` command, in ELF format. Each
//! segment maps `p_paddr` to its file data, and memory not covered by any
//! segment cannot be read. Pages that are only partially covered read as
//! zero in the holes.
//!
//! Each `NT_PRSTATUS` note describes one vCPU in note order, with `pr_pid`
//! equal to the vCPU index plus one. The note carries the general-purpose
//! registers only, so the system registers are read from a separate JSON
//! register file.
//!
//! # Register file
//!
//! The register file is a JSON object with one entry per vCPU, keyed by
//! `cpu<index>`. Each entry holds a `regs` object that maps register names to
//! `0x`-prefixed hexadecimal strings. Other members of an entry, such as
//! `state`, are ignored, and so are registers that the architecture does not
//! use.
//!
//! ```json
//! {
//!   "cpu0": {
//!     "state": "running",
//!     "regs": {
//!       "x30": "0xfffffe002c7e5414",
//!       "sp": "0xfffffe6e9ff9bfc0",
//!       "pc": "0xfffffe002c7e5434",
//!       "TTBR1_EL1": "0x73f88000",
//!       "TCR_EL1": "0x800226511a511"
//!     }
//!   }
//! }
//! ```
//!
//! For ARM64, the register file must provide `pc`, `sp`, `x30`, `SP_EL0`,
//! `SP_EL1`, `TTBR0_EL1`, `TTBR1_EL1`, `TCR_EL1`, `SCTLR_EL1`, `MAIR_EL1`,
//! `VBAR_EL1`, `CONTEXTIDR_EL1`, `ELR_EL1`, `SPSR_EL1`, `ESR_EL1`, `FAR_EL1`,
//! `TPIDR_EL0`, `TPIDR_EL1` and `TPIDRRO_EL0`. The values of `pc`, `sp` and
//! `x30` must equal the values of the `NT_PRSTATUS` note, which guards
//! against pairing a register file with the wrong dump. `TCR_EL1` must match
//! the paging geometry of the architecture. The `sp` of the note replaces
//! the stack pointer bank selected by `pstate`.

mod arch;
mod dump;
mod error;
mod json;
#[cfg(test)]
mod tests;

use std::{fs::File, path::Path};

use memmap2::Mmap;
use vmi_core::{
    Gfn, Pa, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

use self::dump::{Dump, Page};
pub use self::{arch::ArchAdapter, error::Error, json::JsonRegisters};

/// VMI driver for QEMU ELF core dumps.
pub struct VmiQemuCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Parsed dump.
    dump: Dump,

    /// Registers of each vCPU, in note order.
    registers: Vec<Arch::Registers>,
}

impl<Arch> VmiQemuCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a driver for the dump at `dump_path` with the register file at
    /// `registers_path`.
    ///
    /// Validates that the dump is an ELF64 core dump for the architecture's
    /// ELF machine, and merges and validates the registers of every vCPU.
    pub fn new(
        dump_path: impl AsRef<Path>,
        registers_path: impl AsRef<Path>,
    ) -> Result<Self, VmiError> {
        let registers_file = std::fs::read(registers_path)?;

        let file = File::open(dump_path)?;
        // SAFETY: The dump is opened read-only. Modifying the file while it
        // is mapped is undefined behavior, which is the caller's
        // responsibility, as with any memory-mapped file.
        let mmap = unsafe { Mmap::map(&file)? };

        let (dump, registers) = Dump::new(mmap, Arch::ELF_MACHINE, |notes| {
            let json = json::parse(&registers_file, notes.prstatus.len() as u16)?;

            notes
                .prstatus
                .iter()
                .zip(&json)
                .map(|(prstatus, json)| Arch::registers(prstatus, json))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(VmiError::driver)?;

        Ok(Self { dump, registers })
    }
}

impl<Arch> VmiDriver for VmiQemuCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        let max_gfn = match self.dump.end() {
            0 => Gfn(0),
            end => Arch::gfn_from_pa(Pa(end - 1)),
        };

        Ok(VmiInfo {
            page_size: Arch::PAGE_SIZE,
            page_shift: Arch::PAGE_SHIFT,
            max_gfn,
            vcpus: self.registers.len() as u16,
        })
    }
}

impl<Arch> VmiRead for VmiQemuCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let address = match gfn.0.checked_mul(Arch::PAGE_SIZE) {
            Some(address) => address,
            None => return Err(VmiError::OutOfBounds),
        };

        match self.dump.read(address, Arch::PAGE_SIZE) {
            Some(Page::Mapped(range)) => Ok(VmiMappedPage::new(range)),
            Some(Page::Assembled(buffer)) => Ok(VmiMappedPage::new(buffer)),
            None => Err(VmiError::OutOfBounds),
        }
    }
}

impl<Arch> VmiQueryRegisters for VmiQemuCoreDumpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        match self.registers.get(vcpu.0 as usize) {
            Some(registers) => Ok(*registers),
            None => Err(VmiError::OutOfBounds),
        }
    }
}
