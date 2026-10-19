/// An error raised while loading a QEMU migration stream.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The VM description is not valid JSON or does not follow its schema.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The file does not start with the magic number of a migration stream.
    #[error("not a QEMU migration stream (magic {magic:#x})")]
    InvalidMagic {
        /// First four bytes of the file, read as a big-endian number.
        magic: u32,
    },

    /// The stream has a format version other than 3.
    #[error("unsupported migration stream version {version}")]
    UnsupportedVersion {
        /// Format version of the stream.
        version: u32,
    },

    /// An item of the stream runs past the end of the file.
    #[error("migration stream truncated at offset {offset:#x}")]
    Truncated {
        /// File offset of the item.
        offset: u64,
    },

    /// A section or RAM block name is not valid UTF-8.
    #[error("invalid name at offset {offset:#x}")]
    InvalidName {
        /// File offset of the name.
        offset: u64,
    },

    /// The stream does not end with a JSON VM description.
    #[error("migration stream has no VM description")]
    MissingVmDescription,

    /// The end-of-sections marker is not right before the VM description.
    #[error("unexpected data at offset {offset:#x} after the last section")]
    TrailingData {
        /// File offset of the first byte after the end-of-sections marker.
        offset: u64,
    },

    /// The stream has a section type that QEMU does not define.
    #[error("unknown section type {section_type:#x} at offset {offset:#x}")]
    UnknownSectionType {
        /// The section type.
        section_type: u8,

        /// File offset of the section.
        offset: u64,
    },

    /// A device section does not match the next device of the VM
    /// description.
    #[error("unexpected section {name} instance {instance_id} at offset {offset:#x}")]
    UnexpectedSection {
        /// Name of the section.
        name: String,

        /// Instance id of the section.
        instance_id: u32,

        /// File offset of the section.
        offset: u64,
    },

    /// The VM description lists a device section that the stream lacks.
    #[error("missing section {name} instance {instance_id}")]
    MissingSection {
        /// Name of the section.
        name: String,

        /// Instance id of the section.
        instance_id: u32,
    },

    /// The stream has an iterable section other than RAM.
    #[error("unsupported iterable section {name} at offset {offset:#x}")]
    UnsupportedSection {
        /// Name of the section.
        name: String,

        /// File offset of the section.
        offset: u64,
    },

    /// A part of an iterable section refers to a section that did not
    /// start.
    #[error("unknown section id {section_id} at offset {offset:#x}")]
    UnknownSection {
        /// Section id of the part.
        section_id: u32,

        /// File offset of the part.
        offset: u64,
    },

    /// A section footer names a section other than the one before it.
    #[error("section footer for section id {section_id} at offset {offset:#x} does not match")]
    FooterMismatch {
        /// Section id in the footer.
        section_id: u32,

        /// File offset of the footer.
        offset: u64,
    },

    /// A subsection that the VM description lists is not in the stream.
    #[error("missing subsection {name} at offset {offset:#x}")]
    MissingSubsection {
        /// Name of the subsection.
        name: String,

        /// File offset where the subsection should start.
        offset: u64,
    },

    /// The configuration section has a subsection that this driver cannot
    /// read without a description.
    #[error("unknown configuration subsection {name} at offset {offset:#x}")]
    UnknownSubsection {
        /// Name of the subsection.
        name: String,

        /// File offset of the subsection.
        offset: u64,
    },

    /// The stream has a command that only postcopy or COLO migration sends.
    #[error("unsupported migration command {command} at offset {offset:#x}")]
    UnsupportedCommand {
        /// Command number.
        command: u16,

        /// File offset of the command.
        offset: u64,
    },

    /// The stream has no configuration section, which names the machine
    /// type.
    #[error("migration stream has no configuration section")]
    MissingConfiguration,

    /// The source enabled a migration capability that changes the RAM
    /// section or leaves guest memory out of the stream.
    #[error("unsupported migration capability {name}")]
    UnsupportedCapability {
        /// Name of the capability.
        name: String,
    },

    /// A RAM record has flags that this driver does not read, such as an
    /// XBZRLE page or a multifd flush.
    #[error("unsupported RAM flags {flags:#x} at offset {offset:#x}")]
    UnsupportedRamFlags {
        /// Flags of the record.
        flags: u64,

        /// File offset of the record.
        offset: u64,
    },

    /// The list of RAM blocks does not add up to the total RAM size, or names
    /// a block twice.
    #[error("invalid RAM block list at offset {offset:#x}")]
    InvalidRamBlockList {
        /// File offset of the block entry.
        offset: u64,
    },

    /// A RAM record names a block that the list of RAM blocks lacks.
    #[error("unknown RAM block {name} at offset {offset:#x}")]
    UnknownRamBlock {
        /// Name of the block.
        name: String,

        /// File offset of the record.
        offset: u64,
    },

    /// A RAM record continues the previous block, but no record named a
    /// block before it.
    #[error("RAM record at offset {offset:#x} continues no block")]
    NoCurrentRamBlock {
        /// File offset of the record.
        offset: u64,
    },

    /// A RAM record addresses a page past the end of its block.
    #[error(
        "RAM record at offset {offset:#x} addresses {address:#x} past the end of block {block}"
    )]
    RamAddressOutOfBounds {
        /// Name of the block.
        block: String,

        /// Offset of the page within the block.
        address: u64,

        /// File offset of the record.
        offset: u64,
    },

    /// A zero-page record fills its page with a byte other than zero, which
    /// QEMU rejects as well.
    #[error("zero page at offset {offset:#x} is filled with {value:#x}")]
    InvalidZeroPage {
        /// The fill byte.
        value: u8,

        /// File offset of the record.
        offset: u64,
    },

    /// The architecture adapter does not know the machine type.
    #[error("unsupported machine type {machine}")]
    UnsupportedMachine {
        /// The machine type of the stream.
        machine: String,
    },

    /// The stream lacks the RAM block that the machine type uses as its
    /// main RAM.
    #[error("missing RAM block {block}")]
    MissingRamBlock {
        /// Name of the block.
        block: String,
    },

    /// A RAM range that the architecture adapter returned is misaligned, runs
    /// past the end of its block, or overlaps another range. Each range must
    /// be aligned to the target page size.
    #[error("invalid RAM range of block {block} at physical address {address:#x}")]
    InvalidRamRange {
        /// Name of the block.
        block: String,

        /// First guest physical address of the range.
        address: u64,
    },

    /// The page size of the stream does not divide the page size of the
    /// architecture, or the architecture's page is larger than 64 KiB.
    #[error("page size {stream} of the stream does not fit the page size {architecture}")]
    PageSizeMismatch {
        /// The target page size of the stream.
        stream: u64,

        /// The page size of the architecture.
        architecture: u64,
    },

    /// The stream has no `cpu` section.
    #[error("migration stream has no cpu section")]
    NoVcpus,

    /// The instance ids of the `cpu` sections are not the numbers from 0 to
    /// the number of sections minus one.
    #[error("unexpected cpu instance {instance_id}")]
    UnexpectedVcpu {
        /// The instance id that breaks the sequence.
        instance_id: u32,
    },

    /// A `cpu` section lacks a field that the architecture adapter reads.
    #[error("vCPU {vcpu}: missing field {field}")]
    MissingField {
        /// Index of the vCPU.
        vcpu: u16,

        /// Path of the field, with the element index and the struct member.
        field: String,
    },

    /// A field of a `cpu` section has a size that is not 1, 2, 4 or 8 bytes.
    #[error("vCPU {vcpu}: field {field} has {size} bytes")]
    InvalidFieldSize {
        /// Index of the vCPU.
        vcpu: u16,

        /// Path of the field, with the element index and the struct member.
        field: String,

        /// Size of the field in bytes.
        size: u64,
    },

    /// The system register list of a `cpu` section lacks a register.
    #[error("vCPU {vcpu}: missing system register {register}")]
    MissingSystemRegister {
        /// Index of the vCPU.
        vcpu: u16,

        /// Name of the register.
        register: &'static str,
    },

    /// The translation control register does not match the paging geometry
    /// of the architecture.
    #[error("vCPU {vcpu}: TCR_EL1 {tcr:#x} does not match the paging geometry")]
    TranslationControlMismatch {
        /// Index of the vCPU.
        vcpu: u16,

        /// Value of `TCR_EL1`.
        tcr: u64,
    },
}
