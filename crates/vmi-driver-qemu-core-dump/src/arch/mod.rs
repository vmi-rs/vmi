mod arm64;

use vmi_core::Architecture;

use crate::{Error, JsonRegisters};

/// Architecture-specific adapter for QEMU ELF core dumps.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// ELF machine (`e_machine`) of dumps of this architecture.
    const ELF_MACHINE: u16;

    /// Builds the registers of one vCPU from its `NT_PRSTATUS` note
    /// descriptor and its register file entry.
    fn registers(prstatus: &[u8], json: &JsonRegisters) -> Result<Self::Registers, Error>;
}
