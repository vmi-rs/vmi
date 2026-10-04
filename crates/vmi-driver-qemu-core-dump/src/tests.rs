use std::{
    collections::BTreeMap,
    ops::Deref,
    path::{Path, PathBuf},
};

use vmi_arch_arm64::{Arm64, Granule4KVa48, Granule16KVa47};
use vmi_core::{
    Gfn, VcpuId, VmiDriver as _, VmiError,
    driver::{VmiQueryRegisters as _, VmiRead as _},
};

use crate::{ArchAdapter, Error, VmiQemuCoreDumpDriver};

/// `TCR_EL1` with 16KB granules and 47-bit VAs in both halves.
const TCR_16K: u64 = 0x8_0022_6511_a511;

/// ELF machine of AArch64.
const EM_AARCH64: u16 = 183;

/// ELF file type of core dumps.
const ET_CORE: u16 = 4;

/// Temporary file removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    /// Writes `content` into a uniquely named temporary file.
    fn new(name: &str, content: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("vmi-qemu-core-dump-{}-{name}", std::process::id()));
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

/// General-purpose registers of one synthetic vCPU.
#[derive(Clone, Copy)]
struct Vcpu {
    /// Value of `pr_pid`.
    pid: u32,

    /// Registers `x0` to `x30`.
    regs: [u64; 31],

    /// Current stack pointer.
    sp: u64,

    /// Program counter.
    pc: u64,

    /// Processor state.
    pstate: u64,
}

impl Vcpu {
    /// Creates a vCPU with distinct register values derived from `index`.
    fn new(index: u64, pstate: u64) -> Self {
        let mut regs = [0; 31];
        for (number, reg) in regs.iter_mut().enumerate() {
            *reg = (index << 32) | number as u64;
        }

        Self {
            pid: index as u32 + 1,
            regs,
            sp: 0xffff_fe00_0000_8000 + index * 0x1000,
            pc: 0xffff_fe00_0000_4000 + index * 4,
            pstate,
        }
    }

    /// Returns the 392-byte AArch64 `NT_PRSTATUS` descriptor.
    fn prstatus(&self) -> Vec<u8> {
        let mut desc = vec![0u8; 392];
        desc[32..36].copy_from_slice(&self.pid.to_le_bytes());

        let mut values = self.regs.to_vec();
        values.extend([self.sp, self.pc, self.pstate]);
        for (index, value) in values.iter().enumerate() {
            let offset = 112 + index * 8;
            desc[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        desc
    }

    /// Returns the register file entry of the vCPU.
    fn json(&self, tcr: u64) -> BTreeMap<String, String> {
        let mut regs = BTreeMap::new();
        let mut set = |name: &str, value: u64| {
            regs.insert(name.to_string(), format!("{value:#x}"));
        };

        set("x30", self.regs[30]);
        set("sp", self.sp);
        set("pc", self.pc);
        set("SP_EL0", 0x5000);
        set("SP_EL1", 0x6000);
        set("TTBR0_EL1", 0x004c_0001_e04f_4000);
        set("TTBR1_EL1", 0x73f8_8000);
        set("TCR_EL1", tcr);
        set("SCTLR_EL1", 0x1000_fc14_799d);
        set("MAIR_EL1", 0x0044_ff04);
        set("VBAR_EL1", 0xffff_fe00_0000_0800);
        set("CONTEXTIDR_EL1", 0x1f);
        set("ELR_EL1", 0x1_9715_d4b4);
        set("SPSR_EL1", 0x6000_0000);
        set("ESR_EL1", 0x5600_0080);
        set("FAR_EL1", 0x1_0000_0000);
        set("TPIDR_EL0", 0x1);
        set("TPIDR_EL1", 0x2);
        set("TPIDRRO_EL0", 0x3);
        regs
    }
}

/// Builds a little-endian ELF64 core dump.
///
/// `loads` lists `(p_paddr, data)` pairs. Each vCPU becomes one
/// `NT_PRSTATUS` note named `CORE`.
fn build_elf(e_type: u16, machine: u16, vcpus: &[Vcpu], loads: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut notes = Vec::new();
    for vcpu in vcpus {
        let desc = vcpu.prstatus();
        notes.extend(5u32.to_le_bytes());
        notes.extend((desc.len() as u32).to_le_bytes());
        notes.extend(1u32.to_le_bytes());
        notes.extend(b"CORE\0\0\0\0");
        notes.extend(desc);
    }

    let phnum = 1 + loads.len();
    let mut offset = 64 + 56 * phnum as u64;

    let mut phdrs = Vec::new();
    let mut push_phdr = |p_type: u32, offset: u64, paddr: u64, size: u64| {
        phdrs.extend(p_type.to_le_bytes());
        phdrs.extend(0u32.to_le_bytes());
        phdrs.extend(offset.to_le_bytes());
        phdrs.extend(0u64.to_le_bytes());
        phdrs.extend(paddr.to_le_bytes());
        phdrs.extend(size.to_le_bytes());
        phdrs.extend(size.to_le_bytes());
        phdrs.extend(0u64.to_le_bytes());
    };

    push_phdr(4, offset, 0, notes.len() as u64);
    offset += notes.len() as u64;
    for (paddr, data) in loads {
        push_phdr(1, offset, *paddr, data.len() as u64);
        offset += data.len() as u64;
    }

    let mut elf = Vec::new();
    elf.extend([0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend([0; 8]);
    elf.extend(e_type.to_le_bytes());
    elf.extend(machine.to_le_bytes());
    elf.extend(1u32.to_le_bytes());
    elf.extend(0u64.to_le_bytes());
    elf.extend(64u64.to_le_bytes());
    elf.extend(0u64.to_le_bytes());
    elf.extend(0u32.to_le_bytes());
    elf.extend(64u16.to_le_bytes());
    elf.extend(56u16.to_le_bytes());
    elf.extend((phnum as u16).to_le_bytes());
    elf.extend(64u16.to_le_bytes());
    elf.extend(0u16.to_le_bytes());
    elf.extend(0u16.to_le_bytes());
    elf.extend(phdrs);
    elf.extend(notes);
    for (_, data) in loads {
        elf.extend(data);
    }

    elf
}

/// Builds the register file for `vcpus`.
fn build_json(vcpus: &[Vcpu], tcr: u64) -> Vec<u8> {
    let mut root = BTreeMap::new();
    for (index, vcpu) in vcpus.iter().enumerate() {
        let entry = serde_json::json!({
            "state": "running",
            "regs": vcpu.json(tcr),
        });
        root.insert(format!("cpu{index}"), entry);
    }

    serde_json::to_vec(&root).unwrap()
}

/// Returns `size` bytes of a pattern seeded by `seed`.
fn pattern(seed: u8, size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

/// Returns the two vCPUs of the default synthetic dump.
///
/// vCPU 0 runs at EL1h and vCPU 1 at EL0t.
fn default_vcpus() -> [Vcpu; 2] {
    [Vcpu::new(0, 0x3c5), Vcpu::new(1, 0)]
}

/// Returns the `PT_LOAD` segments of the default synthetic dump.
///
/// Pages 0 and 1 are fully covered, pages 2 and 3 are not covered, page 4
/// is split around a 4-byte hole at 0x10038 and page 6 is covered by its
/// first 0x100 bytes only.
fn default_loads() -> Vec<(u64, Vec<u8>)> {
    vec![
        (0x0, pattern(1, 0x8000)),
        (0x10000, pattern(2, 0x38)),
        (0x1003c, pattern(3, 0x4000 - 0x3c)),
        (0x18000, pattern(4, 0x100)),
    ]
}

/// Driver opened on temporary files.
///
/// The driver is declared first so it unmaps the dump before the files are
/// removed.
struct Opened<Arch>
where
    Arch: ArchAdapter,
{
    /// Driver under test.
    driver: VmiQemuCoreDumpDriver<Arch>,

    /// Dump and register file backing the driver.
    _files: [TempFile; 2],
}

impl<Arch> Deref for Opened<Arch>
where
    Arch: ArchAdapter,
{
    type Target = VmiQemuCoreDumpDriver<Arch>;

    fn deref(&self) -> &Self::Target {
        &self.driver
    }
}

/// Writes a dump and a register file and opens them.
fn open<Arch>(name: &str, elf: &[u8], json: &[u8]) -> Result<Opened<Arch>, VmiError>
where
    Arch: ArchAdapter,
{
    let dump = TempFile::new(&format!("{name}.elf"), elf);
    let registers = TempFile::new(&format!("{name}.json"), json);
    let driver = VmiQemuCoreDumpDriver::<Arch>::new(dump.path(), registers.path())?;

    Ok(Opened {
        driver,
        _files: [dump, registers],
    })
}

/// Opens the default synthetic dump.
fn open_default(name: &str) -> Opened<Arm64<Granule16KVa47>> {
    let vcpus = default_vcpus();
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &default_loads());
    open(name, &elf, &build_json(&vcpus, TCR_16K)).unwrap()
}

/// Returns the driver error wrapped in `err`.
fn driver_error(err: VmiError) -> Error {
    match err {
        VmiError::Driver(err) => *err.downcast::<Error>().unwrap(),
        err => panic!("unexpected error: {err}"),
    }
}

#[test]
fn info_reports_vcpus_page_size_and_max_gfn() {
    let driver = open_default("info");
    let info = driver.info().unwrap();

    assert_eq!(info.vcpus, 2);
    assert_eq!(info.page_size, 0x4000);
    assert_eq!(info.page_shift, 14);
    assert_eq!(info.max_gfn, Gfn(6));
}

#[test]
fn read_page_returns_covered_pages() {
    let driver = open_default("covered");
    let expected = pattern(1, 0x8000);

    let page = driver.read_page(Gfn(0)).unwrap();
    assert_eq!(&*page, &expected[..0x4000]);

    let page = driver.read_page(Gfn(1)).unwrap();
    assert_eq!(&*page, &expected[0x4000..]);
}

#[test]
fn read_page_zero_fills_holes_in_split_page() {
    let driver = open_default("split");
    let page = driver.read_page(Gfn(4)).unwrap();

    assert_eq!(page.len(), 0x4000);
    assert_eq!(&page[..0x38], &pattern(2, 0x38)[..]);
    assert_eq!(&page[0x38..0x3c], &[0, 0, 0, 0]);
    assert_eq!(&page[0x3c..], &pattern(3, 0x4000 - 0x3c)[..]);
}

#[test]
fn read_page_zero_fills_partially_covered_page() {
    let driver = open_default("partial");
    let page = driver.read_page(Gfn(6)).unwrap();

    assert_eq!(page.len(), 0x4000);
    assert_eq!(&page[..0x100], &pattern(4, 0x100)[..]);
    assert!(page[0x100..].iter().all(|&byte| byte == 0));
}

#[test]
fn read_page_outside_all_segments_fails() {
    let driver = open_default("outside");

    assert!(matches!(
        driver.read_page(Gfn(2)),
        Err(VmiError::OutOfBounds)
    ));
    assert!(matches!(
        driver.read_page(Gfn(5)),
        Err(VmiError::OutOfBounds)
    ));
    assert!(matches!(
        driver.read_page(Gfn(7)),
        Err(VmiError::OutOfBounds)
    ));
    assert!(matches!(
        driver.read_page(Gfn(u64::MAX)),
        Err(VmiError::OutOfBounds)
    ));
}

#[test]
fn registers_merge_note_and_register_file() {
    let driver = open_default("registers");
    let vcpus = default_vcpus();

    let registers = driver.registers(VcpuId(0)).unwrap();
    assert_eq!(registers.regs, vcpus[0].regs);
    assert_eq!(registers.pc, vcpus[0].pc);
    assert_eq!(registers.pstate, 0x3c5);
    assert_eq!(registers.ttbr0_el1, 0x004c_0001_e04f_4000);
    assert_eq!(registers.ttbr1_el1, 0x73f8_8000);
    assert_eq!(registers.tcr_el1, TCR_16K);
    assert_eq!(registers.contextidr_el1, 0x1f);
    assert_eq!(registers.tpidrro_el0, 0x3);
    // EL1h: the note sp replaces SP_EL1, SP_EL0 comes from the file.
    assert_eq!(registers.sp_el1, vcpus[0].sp);
    assert_eq!(registers.sp_el0, 0x5000);

    let registers = driver.registers(VcpuId(1)).unwrap();
    assert_eq!(registers.regs, vcpus[1].regs);
    assert_eq!(registers.pc, vcpus[1].pc);
    // EL0t: the note sp replaces SP_EL0, SP_EL1 comes from the file.
    assert_eq!(registers.sp_el0, vcpus[1].sp);
    assert_eq!(registers.sp_el1, 0x6000);

    assert!(matches!(
        driver.registers(VcpuId(2)),
        Err(VmiError::OutOfBounds)
    ));
}

#[test]
fn register_mismatch_names_vcpu_and_register() {
    let vcpus = default_vcpus();
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &default_loads());

    let mut json_vcpus = vcpus;
    json_vcpus[1].pc += 4;
    let json = build_json(&json_vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("mismatch", &elf, &json)
            .err()
            .unwrap(),
    );
    match &err {
        Error::RegisterMismatch { vcpu, register, .. } => {
            assert_eq!(*vcpu, 1);
            assert_eq!(*register, "pc");
        }
        err => panic!("unexpected error: {err}"),
    }

    let message = err.to_string();
    assert!(message.contains("vCPU 1"), "{message}");
    assert!(message.contains("pc"), "{message}");
}

#[test]
fn tcr_not_matching_geometry_is_rejected() {
    let vcpus = default_vcpus();
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &default_loads());
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule4KVa48>>("tcr", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(
        err,
        Error::TranslationControlMismatch {
            vcpu: 0,
            tcr: TCR_16K
        }
    ));
}

#[test]
fn missing_vcpu_in_register_file_is_rejected() {
    let vcpus = default_vcpus();
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &default_loads());
    let json = build_json(&vcpus[..1], TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("missing", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(err, Error::MissingVcpu { vcpu: 1 }));
}

#[test]
fn wrong_machine_is_rejected() {
    let vcpus = default_vcpus();
    let elf = build_elf(ET_CORE, 62, &vcpus, &default_loads());
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("machine", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(
        err,
        Error::MachineMismatch {
            expected: EM_AARCH64,
            found: 62
        }
    ));
}

#[test]
fn non_core_file_is_rejected() {
    let vcpus = default_vcpus();
    let elf = build_elf(2, EM_AARCH64, &vcpus, &default_loads());
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("exec", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(err, Error::NotCoreDump { e_type: 2, .. }));
}

#[test]
fn unexpected_pid_is_rejected() {
    let mut vcpus = default_vcpus();
    vcpus[1].pid = 7;
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &default_loads());
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("pid", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(err, Error::UnexpectedPid { vcpu: 1, pid: 7 }));
}

#[test]
fn overlapping_segments_are_rejected() {
    let vcpus = default_vcpus();
    let loads = vec![(0x0, pattern(1, 0x8000)), (0x4000, pattern(2, 0x4000))];
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &loads);
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("overlap", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(
        err,
        Error::OverlappingSegments { address: 0x4000 }
    ));
}

#[test]
fn segment_past_address_space_is_rejected() {
    let vcpus = default_vcpus();
    let loads = vec![(u64::MAX - 0xff, pattern(1, 0x200))];
    let elf = build_elf(ET_CORE, EM_AARCH64, &vcpus, &loads);
    let json = build_json(&vcpus, TCR_16K);

    let err = driver_error(
        open::<Arm64<Granule16KVa47>>("overflow", &elf, &json)
            .err()
            .unwrap(),
    );
    assert!(matches!(
        err,
        Error::SegmentOverflow {
            address: 0xffff_ffff_ffff_ff00
        }
    ));
}
