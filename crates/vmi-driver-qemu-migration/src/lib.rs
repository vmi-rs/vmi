//! VMI driver for QEMU migration streams.
//!
//! Reads the state of a VM from a migration stream that the QEMU `migrate`
//! command wrote to a file, such as with `migrate "exec:cat > vm.mig"`. The
//! driver maps the file into memory. A stream that went through a compressor
//! must be decompressed first.
//!
//! The stream must end with the JSON VM description, which QEMU writes unless
//! the machine property `suppress-vmdesc` is set. The description names each
//! field of each device section and gives its size, so the driver can walk the
//! device sections of any machine.
//!
//! # Memory
//!
//! The RAM section holds the pages of each RAM block, addressed by block name
//! and offset. The machine type decides where the blocks appear in guest
//! physical memory. `ArchAdapter::ram_ranges` maps the main RAM block of each
//! supported machine type:
//!
//! - `Amd64` reads the `pc-i440fx-*` and `pc-q35-*` machines of
//!   qemu-system-x86_64 and qemu-system-i386. Their `pc.ram` block starts at
//!   address 0 and continues at 4 GiB when it does not fit below the PCI hole.
//! - `Arm64` reads the `virt` machine, with `mach-virt.ram` at 1 GiB, and the
//!   `vmapple` machine, with `mach-vmapple.ram` at `0x70000000`.
//!
//! Other RAM blocks, such as firmware, option ROMs and video memory, cannot be
//! read. The last record of a page decides its content. A page that the stream
//! does not hold reads as zero, as it does in a VM that loads the stream.
//!
//! # Registers
//!
//! QEMU saves each vCPU as a device section named `cpu`, with the vCPU index as
//! the instance id. `ArchAdapter::registers` reads the registers from it. For
//! ARM64, the system registers come from the `cpreg` list, which QEMU fills
//! from KVM or from TCG.
//!
//! # Notes
//!
//! The driver rejects streams that it would read wrong. These are streams of
//! postcopy or COLO migration, streams with the `x-ignore-shared` or
//! `mapped-ram` capability, and RAM sections with XBZRLE, multifd or RDMA
//! records.
//!
//! For the x86 machines, the driver assumes the default of the
//! `max-ram-below-4g` machine property, which the stream does not record.

mod arch;
mod cursor;
mod description;
mod error;
mod ram;
mod state;
mod stream;
#[cfg(test)]
mod tests;

use std::{fs::File, path::Path, rc::Rc};

use memmap2::Mmap;
use vmi_core::{
    Gfn, Pa, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};
use zerocopy::IntoBytes as _;

pub use self::{arch::ArchAdapter, error::Error, ram::RamRange, state::CpuState};
use self::{
    ram::{Memory, Page},
    stream::Stream,
};

/// Zeros that back the pages that read as zero.
///
/// The array holds 64-bit integers. It therefore has the alignment of the
/// other pages that the driver returns. 64 KiB is the largest translation
/// granule of the supported architectures.
static ZERO_PAGE: [u64; 0x2000] = [0; 0x2000];

/// VMI driver for QEMU migration streams.
pub struct VmiQemuMigrationDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Guest physical memory.
    memory: Memory,

    /// Registers of each vCPU, indexed by vCPU index.
    registers: Vec<Arch::Registers>,
}

impl<Arch> VmiQemuMigrationDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a driver for the migration stream at `path`.
    ///
    /// Reads all sections of the stream, maps its RAM with
    /// [`ArchAdapter::ram_ranges`] and reads the registers of each vCPU with
    /// [`ArchAdapter::registers`].
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        let file = File::open(path)?;
        // SAFETY: The stream is opened read-only. Modifying the file while it
        // is mapped is undefined behavior, which is the caller's
        // responsibility, as with any memory-mapped file.
        let mmap = unsafe { Mmap::map(&file)? };

        let (end, description) = description::locate(&mmap).map_err(VmiError::driver)?;

        // An architecture page consists of whole stream pages, and a zero
        // page fits into `ZERO_PAGE`.
        let page_size = description.page_size;
        if !page_size.is_power_of_two()
            || Arch::PAGE_SIZE % page_size != 0
            || Arch::PAGE_SIZE > size_of_val(&ZERO_PAGE) as u64
        {
            return Err(VmiError::driver(Error::PageSizeMismatch {
                stream: page_size,
                architecture: Arch::PAGE_SIZE,
            }));
        }

        let stream = stream::read(&mmap, &description, end).map_err(VmiError::driver)?;

        // Mapping the RAM checks the machine type. A stream of another
        // architecture therefore fails on its machine type before a `cpu`
        // field can be missing.
        let blocks = stream
            .ram
            .blocks()
            .iter()
            .map(|block| (block.name.as_str(), block.length))
            .collect::<Vec<_>>();
        let ranges = Arch::ram_ranges(&stream.machine, &blocks).map_err(VmiError::driver)?;
        let registers = registers::<Arch>(&stream).map_err(VmiError::driver)?;

        // The `cpu` sections borrow the mapping. Only the RAM index, which
        // holds file offsets, outlives the stream.
        let ram = stream.ram;
        let memory = Memory::new(Rc::new(mmap), ram, &ranges).map_err(VmiError::driver)?;
        Ok(Self { memory, registers })
    }
}

/// Builds the registers of each vCPU of a stream, indexed by vCPU index.
///
/// The instance ids of the `cpu` sections must be the numbers from 0 to the
/// number of sections minus one, and fewer than `u16::MAX`.
fn registers<Arch>(stream: &Stream) -> Result<Vec<Arch::Registers>, Error>
where
    Arch: ArchAdapter,
{
    if stream.cpus.is_empty() {
        return Err(Error::NoVcpus);
    }

    let mut cpus = stream.cpus.iter().collect::<Vec<_>>();
    cpus.sort_by_key(|(instance_id, _)| *instance_id);

    let mut registers = Vec::with_capacity(cpus.len());
    for (vcpu, (instance_id, state)) in cpus.into_iter().enumerate() {
        if *instance_id as usize != vcpu || vcpu >= u16::MAX as usize {
            return Err(Error::UnexpectedVcpu {
                instance_id: *instance_id,
            });
        }

        registers.push(Arch::registers(&CpuState::new(vcpu as u16, state))?);
    }

    Ok(registers)
}

impl<Arch> VmiDriver for VmiQemuMigrationDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        let max_gfn = match self.memory.end() {
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

impl<Arch> VmiRead for VmiQemuMigrationDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        let address = match gfn.0.checked_mul(Arch::PAGE_SIZE) {
            Some(address) => address,
            None => return Err(VmiError::OutOfBounds),
        };

        match self.memory.read(address, Arch::PAGE_SIZE) {
            Some(Page::Zero) => Ok(VmiMappedPage::new(
                &ZERO_PAGE.as_bytes()[..Arch::PAGE_SIZE as usize],
            )),
            Some(Page::Mapped(data)) => Ok(VmiMappedPage::new(data)),
            Some(Page::Copied(buffer)) => Ok(VmiMappedPage::new(buffer)),
            None => Err(VmiError::OutOfBounds),
        }
    }
}

impl<Arch> VmiQueryRegisters for VmiQemuMigrationDriver<Arch>
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
