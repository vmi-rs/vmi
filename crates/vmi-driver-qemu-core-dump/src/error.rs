/// An error raised while loading a QEMU ELF core dump or its register file.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The ELF file could not be parsed.
    #[error(transparent)]
    Elf(#[from] elf::ParseError),

    /// The register file is not valid JSON or does not follow the schema.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The ELF file is not a 64-bit core dump.
    #[error("not an ELF64 core dump (e_type {e_type}, class {class})")]
    NotCoreDump {
        /// ELF file type.
        e_type: u16,

        /// ELF class name.
        class: &'static str,
    },

    /// The ELF machine does not match the architecture of the driver.
    #[error("ELF machine {found} does not match the expected machine {expected}")]
    MachineMismatch {
        /// Machine expected by the architecture adapter.
        expected: u16,

        /// Machine found in the ELF header.
        found: u16,
    },

    /// The ELF file has no program header table.
    #[error("ELF file has no program headers")]
    NoProgramHeaders,

    /// Two `PT_LOAD` segments cover the same guest physical memory.
    #[error("PT_LOAD segments overlap at physical address {address:#x}")]
    OverlappingSegments {
        /// Start of the second overlapping segment.
        address: u64,
    },

    /// A `PT_LOAD` segment refers to data outside of the file.
    #[error("PT_LOAD segment at physical address {address:#x} exceeds the file")]
    TruncatedSegment {
        /// Start of the segment.
        address: u64,
    },

    /// A `PT_LOAD` segment extends past the end of the physical address
    /// space.
    #[error("PT_LOAD segment at physical address {address:#x} overflows the address space")]
    SegmentOverflow {
        /// Start of the segment.
        address: u64,
    },

    /// The dump has no `NT_PRSTATUS` note.
    #[error("no NT_PRSTATUS notes found")]
    NoVcpus,

    /// The dump has more `NT_PRSTATUS` notes than a `VcpuId` can address.
    #[error("too many NT_PRSTATUS notes ({count})")]
    TooManyVcpus {
        /// Number of `NT_PRSTATUS` notes.
        count: usize,
    },

    /// An `NT_PRSTATUS` note has an unexpected size.
    #[error("vCPU {vcpu}: NT_PRSTATUS note has {size} bytes, expected {expected}")]
    InvalidPrstatus {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Size of the note descriptor.
        size: usize,

        /// Size expected by the architecture adapter.
        expected: usize,
    },

    /// The `pr_pid` field of an `NT_PRSTATUS` note is not the vCPU index plus
    /// one.
    #[error("vCPU {vcpu}: NT_PRSTATUS pr_pid is {pid}, expected {}", vcpu + 1)]
    UnexpectedPid {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Value of `pr_pid`.
        pid: u32,
    },

    /// The register file has no entry for a vCPU of the dump.
    #[error("vCPU {vcpu}: missing \"cpu{vcpu}\" in the register file")]
    MissingVcpu {
        /// Index of the vCPU in note order.
        vcpu: u16,
    },

    /// The register file entry of a vCPU lacks a required register.
    #[error("vCPU {vcpu}: missing register {register} in the register file")]
    MissingRegister {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Name of the register.
        register: String,
    },

    /// A register value in the register file is not a `0x`-prefixed
    /// hexadecimal string.
    #[error("vCPU {vcpu}: register {register} has an invalid value {value:?}")]
    InvalidRegisterValue {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Name of the register.
        register: String,

        /// Raw value from the register file.
        value: String,
    },

    /// A register present in both the note and the register file differs.
    #[error(
        "vCPU {vcpu}: register {register} is {note:#x} in NT_PRSTATUS but {json:#x} in the \
         register file"
    )]
    RegisterMismatch {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Name of the register.
        register: &'static str,

        /// Value from the `NT_PRSTATUS` note.
        note: u64,

        /// Value from the register file.
        json: u64,
    },

    /// The translation control register does not match the paging geometry
    /// of the architecture.
    #[error("vCPU {vcpu}: TCR_EL1 {tcr:#x} does not match the paging geometry")]
    TranslationControlMismatch {
        /// Index of the vCPU in note order.
        vcpu: u16,

        /// Value of `TCR_EL1`.
        tcr: u64,
    },
}
