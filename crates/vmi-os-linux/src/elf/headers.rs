//! ELF layouts and constants.
//!
//! Mirrors the ELF types that the parser reads from `object::elf` with
//! `#[object_mirror]`, and copies the constants it needs as plain integers.
//! This is the only module in the crate that imports from the `object`
//! crate. Everything else goes through [`crate::elf`].

use vmi_macros::object_mirror;

/// Magic number at the start of every ELF file (`ELFMAG`).
pub const ELFMAG: [u8; 4] = ::object::elf::ELFMAG;

/// 32-bit object (`ELFCLASS32`).
pub const ELFCLASS32: u8 = ::object::elf::ELFCLASS32.0;

/// 64-bit object (`ELFCLASS64`).
pub const ELFCLASS64: u8 = ::object::elf::ELFCLASS64.0;

/// Little-endian data (`ELFDATA2LSB`).
pub const ELFDATA2LSB: u8 = ::object::elf::ELFDATA2LSB.0;

/// Intel 80386 (`EM_386`).
pub const EM_386: u16 = ::object::elf::EM_386.0;

/// AMD x86-64 (`EM_X86_64`).
pub const EM_X86_64: u16 = ::object::elf::EM_X86_64.0;

/// Loadable segment (`PT_LOAD`).
pub const PT_LOAD: u32 = ::object::elf::PT_LOAD.0;

/// Dynamic linking information (`PT_DYNAMIC`).
pub const PT_DYNAMIC: u32 = ::object::elf::PT_DYNAMIC.0;

/// Writable segment (`PF_W`).
pub const PF_W: u32 = ::object::elf::PF_W.0;

/// End of the dynamic section (`DT_NULL`).
pub const DT_NULL: i64 = ::object::elf::DT_NULL.0;

/// Address of the SysV hash table (`DT_HASH`).
pub const DT_HASH: i64 = ::object::elf::DT_HASH.0;

/// Address of the string table (`DT_STRTAB`).
pub const DT_STRTAB: i64 = ::object::elf::DT_STRTAB.0;

/// Address of the symbol table (`DT_SYMTAB`).
pub const DT_SYMTAB: i64 = ::object::elf::DT_SYMTAB.0;

/// Address of the relocations with addends (`DT_RELA`).
pub const DT_RELA: i64 = ::object::elf::DT_RELA.0;

/// Total size of the relocations with addends (`DT_RELASZ`).
pub const DT_RELASZ: i64 = ::object::elf::DT_RELASZ.0;

/// Size of one relocation with addend (`DT_RELAENT`).
pub const DT_RELAENT: i64 = ::object::elf::DT_RELAENT.0;

/// Size of the string table (`DT_STRSZ`).
pub const DT_STRSZ: i64 = ::object::elf::DT_STRSZ.0;

/// Size of one symbol (`DT_SYMENT`).
pub const DT_SYMENT: i64 = ::object::elf::DT_SYMENT.0;

/// Offset of the object's name in the string table (`DT_SONAME`).
pub const DT_SONAME: i64 = ::object::elf::DT_SONAME.0;

/// Address of the GNU hash table (`DT_GNU_HASH`).
pub const DT_GNU_HASH: i64 = ::object::elf::DT_GNU_HASH.0;

/// Address of the symbol version table (`DT_VERSYM`).
pub const DT_VERSYM: i64 = ::object::elf::DT_VERSYM.0;

/// Undefined section (`SHN_UNDEF`).
pub const SHN_UNDEF: u16 = ::object::elf::SHN_UNDEF.0;

/// Absolute value, not in a section (`SHN_ABS`).
pub const SHN_ABS: u16 = ::object::elf::SHN_ABS.0;

/// Global symbol (`STB_GLOBAL`).
pub const STB_GLOBAL: u8 = ::object::elf::STB_GLOBAL.0;

/// Weak symbol (`STB_WEAK`).
pub const STB_WEAK: u8 = ::object::elf::STB_WEAK.0;

/// Unique symbol, a GNU extension (`STB_GNU_UNIQUE`).
pub const STB_GNU_UNIQUE: u8 = ::object::elf::STB_GNU_UNIQUE.0;

/// Data object (`STT_OBJECT`).
pub const STT_OBJECT: u8 = ::object::elf::STT_OBJECT.0;

/// Function (`STT_FUNC`).
pub const STT_FUNC: u8 = ::object::elf::STT_FUNC.0;

/// Thread-local variable (`STT_TLS`).
pub const STT_TLS: u8 = ::object::elf::STT_TLS.0;

/// Function whose address a resolver returns, a GNU extension
/// (`STT_GNU_IFUNC`).
pub const STT_GNU_IFUNC: u8 = ::object::elf::STT_GNU_IFUNC.0;

/// Visible to other objects (`STV_DEFAULT`).
pub const STV_DEFAULT: u8 = ::object::elf::STV_DEFAULT.0;

/// Visible to other objects, but not preemptible (`STV_PROTECTED`).
pub const STV_PROTECTED: u8 = ::object::elf::STV_PROTECTED.0;

/// Version that only the object itself binds to (`VERSYM_HIDDEN`).
pub const VERSYM_HIDDEN: u16 = ::object::elf::VERSYM_HIDDEN.0;

/// Offset of a TLS variable from the thread pointer (`R_X86_64_TPOFF64`).
pub const R_X86_64_TPOFF64: u32 = ::object::elf::R_X86_64_TPOFF64.0;

/// Identification bytes at the start of an ELF file.
///
/// # Implementation Details
///
/// Corresponds to `e_ident`.
#[object_mirror(::object::elf::Ident)]
#[derive(Debug, Clone, Copy)]
pub struct Ident {
    /// `ELFMAG`.
    pub magic: [u8; 4],

    /// Class of the file, `ELFCLASS32` or `ELFCLASS64`.
    pub class: u8,

    /// Byte order, `ELFDATA2LSB` or `ELFDATA2MSB`.
    pub data: u8,

    /// Version of the ELF format.
    pub version: u8,

    /// Operating system ABI.
    pub os_abi: u8,

    /// Version of the ABI.
    pub abi_version: u8,

    /// Padding.
    pub padding: [u8; 7],
}

/// Header of a 64-bit ELF file.
///
/// # Implementation Details
///
/// Corresponds to `Elf64_Ehdr`.
#[object_mirror(::object::elf::FileHeader64<::object::LittleEndian>)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader64 {
    /// Identification bytes.
    pub e_ident: Ident,

    /// Type of the file, such as `ET_DYN`.
    pub e_type: u16,

    /// Machine, such as `EM_X86_64`.
    pub e_machine: u16,

    /// Version of the ELF format.
    pub e_version: u32,

    /// Entry point.
    pub e_entry: u64,

    /// File offset of the program headers.
    pub e_phoff: u64,

    /// File offset of the section headers.
    pub e_shoff: u64,

    /// Processor-specific flags.
    pub e_flags: u32,

    /// Size of this header.
    pub e_ehsize: u16,

    /// Size of one program header.
    pub e_phentsize: u16,

    /// Number of program headers.
    pub e_phnum: u16,

    /// Size of one section header.
    pub e_shentsize: u16,

    /// Number of section headers.
    pub e_shnum: u16,

    /// Index of the section that holds the section names.
    pub e_shstrndx: u16,
}

/// Program header of a 64-bit ELF file.
///
/// # Implementation Details
///
/// Corresponds to `Elf64_Phdr`.
#[object_mirror(::object::elf::ProgramHeader64<::object::LittleEndian>)]
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader64 {
    /// Type of the segment, such as `PT_LOAD`.
    pub p_type: u32,

    /// Flags of the segment, such as `PF_W`.
    pub p_flags: u32,

    /// File offset of the segment.
    pub p_offset: u64,

    /// Virtual address of the segment.
    pub p_vaddr: u64,

    /// Physical address of the segment.
    pub p_paddr: u64,

    /// Size of the segment in the file.
    pub p_filesz: u64,

    /// Size of the segment in memory.
    pub p_memsz: u64,

    /// Alignment of the segment.
    pub p_align: u64,
}

/// Entry in the dynamic section of a 64-bit ELF file.
///
/// # Implementation Details
///
/// Corresponds to `Elf64_Dyn`.
#[object_mirror(::object::elf::Dyn64<::object::LittleEndian>)]
#[derive(Debug, Clone, Copy)]
pub struct Dyn64 {
    /// Tag, such as `DT_SYMTAB`.
    pub d_tag: i64,

    /// Value or address.
    pub d_val: u64,
}

/// Symbol of a 64-bit ELF file.
///
/// # Implementation Details
///
/// Corresponds to `Elf64_Sym`.
#[object_mirror(::object::elf::Sym64<::object::LittleEndian>)]
#[derive(Debug, Clone, Copy)]
pub struct Sym64 {
    /// Offset of the name in the string table.
    pub st_name: u32,

    /// Binding in the high four bits, type in the low four.
    pub st_info: u8,

    /// Visibility in the low two bits.
    pub st_other: u8,

    /// Index of the section that defines the symbol.
    pub st_shndx: u16,

    /// Value, usually an address in the file's view.
    pub st_value: u64,

    /// Size.
    pub st_size: u64,
}

/// Relocation with addend of a 64-bit ELF file.
///
/// # Implementation Details
///
/// Corresponds to `Elf64_Rela`.
#[object_mirror(::object::elf::Rela64<::object::LittleEndian>)]
#[derive(Debug, Clone, Copy)]
pub struct Rela64 {
    /// Address in the file's view that the relocation writes.
    pub r_offset: u64,

    /// Symbol index in the high 32 bits, type in the low 32 bits.
    pub r_info: u64,

    /// Addend.
    pub r_addend: i64,
}
