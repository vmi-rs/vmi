use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use vmi_arch_amd64::Amd64;
use vmi_arch_arm64::{Arm64, Granule4KVa48, Granule16KVa47};
use vmi_core::{
    Gfn, VcpuId, VmiError,
    driver::{VmiQueryRegisters as _, VmiRead as _},
};

use crate::{ArchAdapter, Error, VmiQemuMigrationDriver};

/// Target page size of the synthetic streams.
const PAGE_SIZE: u64 = 0x1000;

/// Name of the main RAM block of the `virt` machine.
const VIRT_RAM: &str = "mach-virt.ram";

/// Guest frame number of the first page of `mach-virt.ram` with 4KB pages.
const VIRT_RAM_GFN: u64 = 0x4_0000;

/// `TCR_EL1` with 16KB granules and 47-bit VAs in both halves.
const TCR_16K: u64 = 0x8_0022_6511_a511;

/// Temporary file removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    /// Writes `content` into a uniquely named temporary file.
    fn new(name: &str, content: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("vmi-qemu-migration-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }

    /// Returns the path of the file.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A writer of a synthetic migration stream and its VM description.
struct StreamWriter {
    /// Bytes of the stream.
    data: Vec<u8>,

    /// Machine type of the configuration section.
    machine: String,

    /// Device entries of the VM description.
    devices: Vec<Value>,

    /// Section id of the next device section.
    next_section: u32,
}

impl StreamWriter {
    /// Starts a stream with the configuration section of `machine`.
    fn new(machine: &str) -> Self {
        let mut writer = Self {
            data: Vec::new(),
            machine: machine.into(),
            devices: Vec::new(),
            next_section: 3,
        };

        writer.be32(0x5145_564d);
        writer.be32(3);
        writer.data.push(0x07);
        writer.be32(machine.len() as u32);
        writer.data.extend(machine.as_bytes());
        writer
    }

    /// Writes a big-endian 32-bit integer.
    fn be32(&mut self, value: u32) {
        self.data.extend(value.to_be_bytes());
    }

    /// Writes a big-endian 64-bit integer.
    fn be64(&mut self, value: u64) {
        self.data.extend(value.to_be_bytes());
    }

    /// Writes a name with a one-byte length.
    fn name(&mut self, name: &str) {
        self.data.push(name.len() as u8);
        self.data.extend(name.as_bytes());
    }

    /// Writes the start of the RAM section with the list of RAM blocks.
    fn ram_start(&mut self, blocks: &[(&str, u64)]) {
        self.data.push(0x01);
        self.be32(2);
        self.name("ram");
        self.be32(0);
        self.be32(4);

        let total = blocks.iter().map(|(_, length)| length).sum::<u64>();
        self.be64(total | 0x04);
        for (name, length) in blocks {
            self.name(name);
            self.be64(*length);
        }

        self.ram_end_of_section();
    }

    /// Writes the header of a part of the RAM section.
    fn ram_part(&mut self) {
        self.data.push(0x02);
        self.be32(2);
    }

    /// Writes a page record filled with `value` and returns the file offset
    /// of its data.
    ///
    /// `block` names the block, or is `None` to continue the block of the
    /// previous record.
    fn page(&mut self, block: Option<&str>, offset: u64, value: u8) -> usize {
        self.page_header(block, offset | 0x08);
        let start = self.data.len();
        self.data
            .extend(std::iter::repeat_n(value, PAGE_SIZE as usize));
        start
    }

    /// Writes a zero-page record.
    fn zero_page(&mut self, block: Option<&str>, offset: u64) {
        self.page_header(block, offset | 0x02);
        self.data.push(0);
    }

    /// Writes the header of a page record.
    fn page_header(&mut self, block: Option<&str>, header: u64) {
        match block {
            Some(block) => {
                self.be64(header);
                self.name(block);
            }
            None => self.be64(header | 0x20),
        }
    }

    /// Writes the record that ends a part of the RAM section and the footer
    /// of the RAM section.
    fn ram_end_of_section(&mut self) {
        self.be64(0x10);
        self.data.push(0x7e);
        self.be32(2);
    }

    /// Writes a device section of integer fields and describes it.
    ///
    /// Each field is its name, the size of one element and the elements.
    fn device(&mut self, name: &str, instance_id: u32, fields: &[(&str, u64, &[u64])]) {
        let section = self.next_section;
        self.next_section += 1;

        self.data.push(0x04);
        self.be32(section);
        self.name(name);
        self.be32(instance_id);
        self.be32(1);

        let mut descriptions = Vec::new();
        for (field, size, values) in fields {
            for value in *values {
                let bytes = value.to_be_bytes();
                self.data.extend(&bytes[8 - *size as usize..]);
            }

            let mut description = json!({
                "name": field,
                "type": format!("uint{}", size * 8),
                "size": size,
            });
            if values.len() > 1 {
                description["array_len"] = json!(values.len());
            }

            descriptions.push(description);
        }

        self.data.push(0x7e);
        self.be32(section);
        self.devices.push(json!({
            "name": name,
            "instance_id": instance_id,
            "vmsd_name": name,
            "version": 1,
            "fields": descriptions,
        }));
    }

    /// Ends the sections and appends the VM description.
    fn finish(mut self) -> Vec<u8> {
        self.data.push(0x00);

        let description = json!({
            "configuration": {
                "vmsd_name": "configuration",
                "version": 1,
                "fields": [
                    { "name": "len", "type": "uint32", "size": 4 },
                    { "name": "name", "type": "buffer", "size": self.machine.len() },
                ],
            },
            "page_size": PAGE_SIZE,
            "devices": self.devices,
        });

        let text = serde_json::to_vec(&description).unwrap();
        self.data.push(0x06);
        self.be32(text.len() as u32);
        self.data.extend(text);
        self.data
    }
}

/// Returns the KVM register index of an AArch64 system register.
fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    0x6030_0000_0013_0000 | (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

/// A synthetic stream of a `virt` machine with one vCPU.
struct VirtStream {
    /// Bytes of the stream.
    data: Vec<u8>,

    /// File offset of the data of the first page record.
    first_page: usize,
}

/// Builds a stream of a `virt` machine with 64 KiB of RAM and one vCPU.
///
/// The RAM holds page 0 filled with `0x11` and page 2 filled with `0x44`,
/// which overwrites an earlier record with `0x33`. Page 1 has a zero-page
/// record, and the other pages have no record.
fn virt_stream(sctlr: u64, tcr: u64) -> VirtStream {
    let mut writer = StreamWriter::new("virt-10.2");
    writer.ram_start(&[(VIRT_RAM, 0x1_0000), ("virt.flash0", 0x1000)]);

    writer.ram_part();
    let first_page = writer.page(Some(VIRT_RAM), 0, 0x11);
    writer.zero_page(None, PAGE_SIZE);
    writer.page(None, 2 * PAGE_SIZE, 0x33);
    writer.page(Some("virt.flash0"), 0, 0x55);
    writer.ram_end_of_section();

    writer.ram_part();
    writer.page(Some(VIRT_RAM), 2 * PAGE_SIZE, 0x44);
    writer.ram_end_of_section();

    writer.device("timer", 0, &[("cpu_ticks_offset", 8, &[7])]);

    let mut xregs = (0..32).map(|index| 0x1000 + index).collect::<Vec<_>>();
    xregs[31] = 0xffff_8000_0000_3ff0;

    let indexes = [
        sysreg(3, 0, 1, 0, 0),
        sysreg(3, 0, 2, 0, 0),
        sysreg(3, 0, 2, 0, 1),
        sysreg(3, 0, 2, 0, 2),
        sysreg(3, 0, 5, 2, 0),
        sysreg(3, 0, 6, 0, 0),
        sysreg(3, 0, 10, 2, 0),
        sysreg(3, 0, 12, 0, 0),
        sysreg(3, 0, 13, 0, 1),
        sysreg(3, 0, 13, 0, 4),
        sysreg(3, 3, 13, 0, 2),
        sysreg(3, 3, 13, 0, 3),
    ];
    let values = [
        sctlr, 0x10, 0x4_2000, tcr, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
    ];

    writer.device(
        "cpu",
        0,
        &[
            ("env.xregs", 8, &xregs),
            ("env.pc", 8, &[0xffff_8000_0001_0000]),
            ("cpsr", 4, &[0x3c5]),
            ("env.sp_el", 8, &[0xa000, 0xb000, 0, 0]),
            ("env.elr_el", 8, &[0, 0xc000, 0, 0]),
            ("env.banked_spsr", 8, &[0, 0x3c4, 0, 0, 0, 0, 0, 0]),
            ("cpreg_vmstate_indexes", 8, &indexes),
            ("cpreg_vmstate_values", 8, &values),
        ],
    );

    VirtStream {
        data: writer.finish(),
        first_page,
    }
}

/// Reads one page through the driver.
fn read<Arch>(driver: &VmiQemuMigrationDriver<Arch>, gfn: u64) -> Result<Vec<u8>, VmiError>
where
    Arch: ArchAdapter,
{
    let page = driver.read_page(Gfn(gfn))?;
    assert_eq!(
        page.as_ptr() as usize % 8,
        0,
        "page {gfn:#x} is not aligned"
    );
    Ok(page.to_vec())
}

#[test]
fn reads_ram_of_the_last_record() {
    let stream = virt_stream(0, 0);
    assert_ne!(
        stream.first_page % 8,
        0,
        "first page data must be unaligned"
    );
    let file = TempFile::new("last-record", &stream.data);
    let driver = VmiQemuMigrationDriver::<Arm64<Granule4KVa48>>::new(file.path()).unwrap();

    assert_eq!(read(&driver, VIRT_RAM_GFN).unwrap(), vec![0x11; 0x1000]);
    assert_eq!(read(&driver, VIRT_RAM_GFN + 1).unwrap(), vec![0; 0x1000]);
    assert_eq!(read(&driver, VIRT_RAM_GFN + 2).unwrap(), vec![0x44; 0x1000]);
    assert_eq!(read(&driver, VIRT_RAM_GFN + 3).unwrap(), vec![0; 0x1000]);

    // Only the main RAM block appears in guest physical memory.
    assert!(matches!(
        read(&driver, VIRT_RAM_GFN - 1),
        Err(VmiError::OutOfBounds)
    ));
    assert!(matches!(
        read(&driver, VIRT_RAM_GFN + 16),
        Err(VmiError::OutOfBounds)
    ));
}

#[test]
fn assembles_large_pages() {
    let stream = virt_stream(0, 0);
    let file = TempFile::new("large-pages", &stream.data);
    let driver = VmiQemuMigrationDriver::<Arm64<Granule16KVa47>>::new(file.path()).unwrap();

    let mut expected = vec![0x11; 0x1000];
    expected.extend([0; 0x1000]);
    expected.extend([0x44; 0x1000]);
    expected.extend([0; 0x1000]);
    assert_eq!(read(&driver, VIRT_RAM_GFN / 4).unwrap(), expected);
    assert_eq!(
        read(&driver, VIRT_RAM_GFN / 4 + 1).unwrap(),
        vec![0; 0x4000]
    );
}

#[test]
fn takes_the_current_stack_pointer_from_xregs() {
    let stream = virt_stream(0, 0);
    let file = TempFile::new("registers", &stream.data);
    let driver = VmiQemuMigrationDriver::<Arm64<Granule4KVa48>>::new(file.path()).unwrap();
    let registers = driver.registers(VcpuId(0)).unwrap();

    assert_eq!(registers.regs[0], 0x1000);
    assert_eq!(registers.regs[30], 0x101e);
    assert_eq!(registers.pc, 0xffff_8000_0001_0000);
    assert_eq!(registers.pstate, 0x3c5);
    assert_eq!(registers.sp_el0, 0xa000);
    // PSTATE selects SP_EL1, whose bank in `env.sp_el` is stale.
    assert_eq!(registers.sp_el1, 0xffff_8000_0000_3ff0);
    assert_eq!(registers.elr_el1, 0xc000);
    assert_eq!(registers.spsr_el1, 0x3c4);
    assert_eq!(registers.ttbr0_el1, 0x10);
    assert_eq!(registers.ttbr1_el1, 0x4_2000);
    assert_eq!(registers.tpidrro_el0, 0x90);
    assert!(matches!(
        driver.registers(VcpuId(1)),
        Err(VmiError::OutOfBounds)
    ));
}

#[test]
fn checks_the_paging_geometry_only_with_the_mmu_on() {
    let stream = virt_stream(1, TCR_16K);
    let file = TempFile::new("geometry", &stream.data);
    assert!(VmiQemuMigrationDriver::<Arm64<Granule16KVa47>>::new(file.path()).is_ok());

    let err = match VmiQemuMigrationDriver::<Arm64<Granule4KVa48>>::new(file.path()) {
        Ok(_) => panic!("TCR_EL1 of 16KB pages accepted for 4KB pages"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("TCR_EL1"), "{err}");

    let stream = virt_stream(0, TCR_16K);
    let file = TempFile::new("geometry-off", &stream.data);
    assert!(VmiQemuMigrationDriver::<Arm64<Granule4KVa48>>::new(file.path()).is_ok());
}

/// Returns the RAM ranges of a PC machine with `ram_size` bytes of RAM.
fn pc_ranges(machine: &str, ram_size: u64) -> Vec<(u64, u64, u64)> {
    Amd64::ram_ranges(machine, &[("pc.bios", 0x4_0000), ("pc.ram", ram_size)])
        .unwrap()
        .into_iter()
        .map(|range| {
            assert_eq!(range.block, "pc.ram");
            (range.offset, range.address, range.length)
        })
        .collect()
}

#[test]
fn splits_pc_ram_at_the_pci_hole() {
    const GIB: u64 = 1 << 30;

    assert_eq!(
        pc_ranges("pc-q35-10.2", 0xb000_0000 - 0x1000),
        [(0, 0, 0xb000_0000 - 0x1000)]
    );
    assert_eq!(
        pc_ranges("pc-q35-10.2", 0xb000_0000),
        [(0, 0, 2 * GIB), (2 * GIB, 4 * GIB, 0x3000_0000)]
    );
    assert_eq!(
        pc_ranges("pc-i440fx-10.2", 0xe000_0000 - 0x1000),
        [(0, 0, 0xe000_0000 - 0x1000)]
    );
    assert_eq!(
        pc_ranges("pc-i440fx-10.2", 0xe000_0000),
        [(0, 0, 3 * GIB), (3 * GIB, 4 * GIB, 0x2000_0000)]
    );

    assert!(matches!(
        Amd64::ram_ranges("virt-10.2", &[("pc.ram", GIB)]),
        Err(Error::UnsupportedMachine { .. })
    ));
}
