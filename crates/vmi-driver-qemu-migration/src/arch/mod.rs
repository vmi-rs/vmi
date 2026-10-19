mod amd64;
mod arm64;

use vmi_core::Architecture;

use crate::{CpuState, Error, RamRange};

/// Architecture-specific adapter for QEMU migration streams.
///
/// The adapter knows the machine types of its architecture and the fields
/// of the `cpu` sections that its QEMU target writes.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Returns where the RAM blocks of a machine appear in guest physical
    /// memory.
    ///
    /// `machine` is the machine type that the configuration section of the
    /// stream names, such as `pc-q35-10.2`. `blocks` holds the name and the
    /// length of each RAM block of the stream, in stream order.
    fn ram_ranges(machine: &str, blocks: &[(&str, u64)]) -> Result<Vec<RamRange>, Error>;

    /// Builds the registers of one vCPU from its `cpu` section.
    fn registers(cpu: &CpuState) -> Result<Self::Registers, Error>;
}

/// Returns the length of the RAM block named `block`.
fn block_length(blocks: &[(&str, u64)], block: &str) -> Result<u64, Error> {
    match blocks.iter().find(|(name, _)| *name == block) {
        Some((_, length)) => Ok(*length),
        None => Err(Error::MissingRamBlock {
            block: block.into(),
        }),
    }
}
