//! ELF images in guest memory.
//!
//! The types here mirror the ones in `object::elf` that the crate reads, as
//! packed structs with native fields, and the constants are plain integers.
//! [`ElfImage`] holds the ELF header, the program headers and the dynamic
//! section of an image in user space, and [`LinuxImage::elf`] and
//! [`LinuxUserModule::elf`] return it.
//!
//! The loaders map the ELF header, the program headers and the dynamic
//! section of an image, and the tables that the dynamic section points to.
//! They also map the notes, which the linkers put into a `PT_LOAD` segment.
//! The parser reads only those parts. Section headers are not mapped.
//!
//! Addresses in the file's view become addresses in memory by adding the
//! load bias. glibc also adds the bias to the pointers in a writable dynamic
//! section, once ld.so processes the object (`elf/get-dynamic-info.h`). The
//! parser therefore accepts a pointer in either form.
//!
//! [`LinuxImage::elf`]: crate::LinuxImage::elf
//! [`LinuxUserModule::elf`]: crate::LinuxUserModule::elf

mod headers;
mod note;

use vmi_core::{
    Pa, Va, VmiError, VmiState,
    driver::VmiRead,
    os::{VmiOsImageArchitecture, VmiOsImageSymbol},
};
use zerocopy::FromBytes;

pub(crate) use self::note::read_build_id;
pub use self::{
    headers::{
        DT_GNU_HASH, DT_HASH, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_SONAME, DT_STRSZ,
        DT_STRTAB, DT_SYMENT, DT_SYMTAB, DT_VERSYM, Dyn64, ELF_NOTE_GNU, ELFCLASS32, ELFCLASS64,
        ELFDATA2LSB, ELFMAG, EM_386, EM_X86_64, FileHeader64, Ident, NT_GNU_BUILD_ID, NoteHeader64,
        PF_W, PT_DYNAMIC, PT_LOAD, PT_NOTE, ProgramHeader64, R_X86_64_TPOFF64, Rela64, SHN_ABS,
        SHN_UNDEF, STB_GLOBAL, STB_GNU_UNIQUE, STB_WEAK, STT_FUNC, STT_GNU_IFUNC, STT_OBJECT,
        STT_TLS, STV_DEFAULT, STV_PROTECTED, Sym64, VERSYM_HIDDEN,
    },
    note::BuildId,
};
use crate::{ArchAdapter, LinuxError, LinuxOs};

/// Size of a page.
const PAGE_SIZE: u64 = 0x1000;

/// Upper limit for an image's program headers.
const PROGRAM_HEADERS_MAX: usize = 256;

/// Upper limit of the entries in a dynamic section.
const DYNAMIC_ENTRIES_MAX: usize = 4096;

/// Upper limit of the symbols in a symbol table.
const SYMBOLS_MAX: usize = 1 << 20;

/// Upper limit for a string table's size.
const STRINGS_MAX: usize = 1 << 24;

/// Upper limit of the relocations that a search reads.
const RELOCATIONS_MAX: usize = 1 << 20;

/// Upper limit for the length of the object's name.
const SONAME_MAX: usize = 256;

/// Source for the bytes of an ELF image.
pub(crate) trait ElfReader {
    /// Reads the bytes at a virtual address.
    fn read(&self, va: Va, buffer: &mut [u8]) -> Result<(), VmiError>;
}

/// Reads ELF images from guest memory.
pub(crate) struct GuestElfReader<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Translation root of the address space, or `None` for the root that
    /// the operating system picks for the state.
    root: Option<Pa>,
}

impl<'a, Driver> GuestElfReader<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a reader for the address space with the given root, or for
    /// the state's address space with `None`.
    pub(crate) fn new(vmi: VmiState<'a, LinuxOs<Driver>>, root: Option<Pa>) -> Self {
        Self { vmi, root }
    }
}

impl<Driver> ElfReader for GuestElfReader<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn read(&self, va: Va, buffer: &mut [u8]) -> Result<(), VmiError> {
        match self.root {
            Some(root) => self.vmi.read_in((va, root), buffer),
            None => self.vmi.read(va, buffer),
        }
    }
}

/// Returns the architecture of the ELF image at a base address, or `None`
/// for a machine other than x86.
pub(crate) fn architecture(
    reader: &impl ElfReader,
    base: Va,
) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
    let header = read_header(reader, base)?;

    match (header.e_ident.class, header.e_machine) {
        (ELFCLASS64, EM_X86_64) => Ok(Some(VmiOsImageArchitecture::Amd64)),
        (ELFCLASS32, EM_386) => Ok(Some(VmiOsImageArchitecture::X86)),
        _ => Ok(None),
    }
}

/// Checks if the bytes at a base address start with the ELF magic number.
pub(crate) fn is_elf(reader: &impl ElfReader, base: Va) -> Result<bool, VmiError> {
    let mut magic = [0; ELFMAG.len()];
    reader.read(base, &mut magic)?;
    Ok(magic == ELFMAG)
}

/// Reads the ELF header at a base address and checks its magic number.
fn read_header(reader: &impl ElfReader, base: Va) -> Result<FileHeader64, VmiError> {
    let mut buffer = [0; size_of::<FileHeader64>()];
    reader.read(base, &mut buffer)?;

    let header = parse::<FileHeader64>(&buffer, "ELF header")?;
    let magic = header.e_ident.magic;
    if magic != ELFMAG {
        return Err(LinuxError::CorruptedImage("ELF magic").into());
    }

    Ok(header)
}

/// Parses a value from the start of a byte slice.
fn parse<T>(bytes: &[u8], what: &'static str) -> Result<T, VmiError>
where
    T: FromBytes,
{
    match T::read_from_prefix(bytes) {
        Ok((value, _)) => Ok(value),
        Err(_) => Err(LinuxError::CorruptedImage(what).into()),
    }
}

/// Reads bytes at a virtual address into a new buffer.
fn read_bytes(reader: &impl ElfReader, va: Va, length: usize) -> Result<Vec<u8>, VmiError> {
    let mut buffer = vec![0; length];
    reader.read(va, &mut buffer)?;
    Ok(buffer)
}

/// Reads a little-endian 32-bit value at a virtual address.
fn read_u32(reader: &impl ElfReader, va: Va) -> Result<u32, VmiError> {
    let mut buffer = [0; size_of::<u32>()];
    reader.read(va, &mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

/// Converts a size from the image into a `usize` within a limit.
fn checked_size(value: u64, limit: usize, what: &'static str) -> Result<usize, VmiError> {
    match usize::try_from(value) {
        Ok(value) if value <= limit => Ok(value),
        _ => Err(LinuxError::CorruptedImage(what).into()),
    }
}

/// Returns the null-terminated string at an offset of a string table.
fn string_at(strings: &[u8], offset: u32) -> Result<&[u8], VmiError> {
    let tail = match strings.get(offset as usize..) {
        Some(tail) => tail,
        None => return Err(LinuxError::CorruptedImage("ELF string offset").into()),
    };

    match memchr::memchr(0, tail) {
        Some(end) => Ok(&tail[..end]),
        None => Err(LinuxError::CorruptedImage("ELF string").into()),
    }
}

/// The dynamic entries that the parser uses, with the pointers resolved to
/// addresses in memory.
#[derive(Debug, Clone, Copy, Default)]
struct Dynamic {
    /// The SysV hash table (`DT_HASH`).
    hash: Option<Va>,

    /// The GNU hash table (`DT_GNU_HASH`).
    gnu_hash: Option<Va>,

    /// The symbol table (`DT_SYMTAB`).
    symtab: Option<Va>,

    /// The string table (`DT_STRTAB`).
    strtab: Option<Va>,

    /// Size of the string table (`DT_STRSZ`).
    strsz: Option<u64>,

    /// Size of one symbol (`DT_SYMENT`).
    syment: Option<u64>,

    /// The symbol version table (`DT_VERSYM`).
    versym: Option<Va>,

    /// Offset of the object's name in the string table (`DT_SONAME`).
    soname: Option<u64>,

    /// The relocations with addends (`DT_RELA`).
    rela: Option<Va>,

    /// Total size of the relocations with addends (`DT_RELASZ`).
    relasz: Option<u64>,

    /// Size of one relocation with addend (`DT_RELAENT`).
    relaent: Option<u64>,
}

/// An image's dynamic symbol table, in a buffer.
struct SymbolTable {
    /// The symbols.
    symbols: Vec<u8>,

    /// Size of one symbol.
    entry_size: usize,

    /// The string table.
    strings: Vec<u8>,

    /// The symbol versions, two bytes per symbol, if the image has them.
    versions: Option<Vec<u8>>,
}

impl SymbolTable {
    /// Returns the symbol at an index with its name.
    fn get(&self, index: usize) -> Result<(Sym64, &[u8]), VmiError> {
        let start = index * self.entry_size;
        let bytes = match self.symbols.get(start..start + self.entry_size) {
            Some(bytes) => bytes,
            None => return Err(LinuxError::CorruptedImage("ELF symbol index").into()),
        };

        let symbol = parse::<Sym64>(bytes, "ELF symbol")?;
        let name = string_at(&self.strings, symbol.st_name)?;
        Ok((symbol, name))
    }

    /// Returns the number of symbols.
    fn len(&self) -> usize {
        self.symbols.len() / self.entry_size
    }

    /// Checks if the symbol at an index has a hidden version, which leaves
    /// its name's default version to another symbol.
    fn is_hidden(&self, index: usize) -> bool {
        let versions = match &self.versions {
            Some(versions) => versions,
            None => return false,
        };

        match versions.get(index * 2..index * 2 + 2) {
            Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]) & VERSYM_HIDDEN != 0,
            None => false,
        }
    }
}

/// Checks if a symbol is an export: a function or a data object that the
/// image defines and other objects can see.
fn is_export(symbol: &Sym64) -> bool {
    let section = symbol.st_shndx;
    let binding = symbol.st_info >> 4;
    let kind = symbol.st_info & 0x0f;
    let visibility = symbol.st_other & 0x03;

    section != SHN_UNDEF
        && section != SHN_ABS
        && matches!(binding, STB_GLOBAL | STB_WEAK | STB_GNU_UNIQUE)
        && matches!(kind, STT_FUNC | STT_OBJECT | STT_GNU_IFUNC)
        && matches!(visibility, STV_DEFAULT | STV_PROTECTED)
}

/// A 64-bit ELF image in guest memory, as its program headers and its
/// dynamic section describe it.
#[derive(Debug, Clone)]
pub struct ElfImage {
    /// Address of the ELF header, the image base.
    base: Va,

    /// The ELF header.
    header: FileHeader64,

    /// The program headers.
    program_headers: Vec<ProgramHeader64>,

    /// Difference between an address in memory and the same address in the
    /// file's view, the load bias.
    bias: u64,

    /// Lowest address of a `PT_LOAD` segment in the file's view, rounded
    /// down to a page.
    start: u64,

    /// Size from `start` to the highest end of a `PT_LOAD` segment, rounded
    /// up to a page.
    span: u64,

    /// The entries of the dynamic section before `DT_NULL`, as the section
    /// holds them.
    dynamic_entries: Vec<Dyn64>,

    /// The dynamic entries that the parser uses. An image without a dynamic
    /// segment has none.
    dynamic: Dynamic,
}

impl ElfImage {
    /// Parses the headers and the dynamic section of the image at a base
    /// address.
    ///
    /// Only little-endian 64-bit images are parsed. Others give
    /// `VmiError::NotSupported`.
    pub(crate) fn parse(reader: &impl ElfReader, base: Va) -> Result<Self, VmiError> {
        let header = read_header(reader, base)?;
        if header.e_ident.class != ELFCLASS64 || header.e_ident.data != ELFDATA2LSB {
            return Err(VmiError::NotSupported);
        }

        let entry_size = usize::from(header.e_phentsize);
        let count = usize::from(header.e_phnum);
        if entry_size < size_of::<ProgramHeader64>() || count > PROGRAM_HEADERS_MAX {
            return Err(LinuxError::CorruptedImage("ELF program headers").into());
        }

        let bytes = read_bytes(reader, base + header.e_phoff, entry_size * count)?;

        let mut start = u64::MAX;
        let mut end = 0;
        let mut dynamic = None;
        let mut program_headers = Vec::with_capacity(count);

        for bytes in bytes.chunks_exact(entry_size) {
            let program = parse::<ProgramHeader64>(bytes, "ELF program header")?;

            match program.p_type {
                PT_LOAD => {
                    let segment_end = match program.p_vaddr.checked_add(program.p_memsz) {
                        Some(segment_end) => segment_end,
                        None => return Err(LinuxError::CorruptedImage("ELF segment").into()),
                    };

                    start = start.min(program.p_vaddr);
                    end = end.max(segment_end);
                }
                PT_DYNAMIC => dynamic = Some(program),
                _ => {}
            }

            program_headers.push(program);
        }

        if start > end {
            return Err(LinuxError::CorruptedImage("ELF load segments").into());
        }

        let start = start & !(PAGE_SIZE - 1);
        let end = match end.checked_next_multiple_of(PAGE_SIZE) {
            Some(end) => end,
            None => return Err(LinuxError::CorruptedImage("ELF segment").into()),
        };

        let mut image = Self {
            base,
            header,
            program_headers,
            bias: base.0.wrapping_sub(start),
            start,
            span: end - start,
            dynamic_entries: Vec::new(),
            dynamic: Dynamic::default(),
        };

        if let Some(program) = dynamic {
            (image.dynamic_entries, image.dynamic) = image.read_dynamic(reader, &program)?;
        }

        Ok(image)
    }

    /// Returns the image's size in memory, from its lowest `PT_LOAD` segment
    /// to the end of its highest one, `.bss` included.
    pub fn size(&self) -> u64 {
        self.span
    }

    /// Returns the load bias, which turns an address in the file's view into
    /// the same address in memory.
    ///
    /// # Implementation Details
    ///
    /// The base address minus the lowest `PT_LOAD` address, rounded down to a
    /// page, as `link_map.l_addr` in glibc.
    pub fn load_bias(&self) -> u64 {
        self.bias
    }

    /// Returns the ELF header.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `Elf64_Ehdr` at the base address.
    pub fn file_header(&self) -> &FileHeader64 {
        &self.header
    }

    /// Returns the program headers.
    ///
    /// Their addresses are in the file's view. Adding the
    /// [load bias](Self::load_bias) gives the addresses in memory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `Elf64_Phdr` entries at `e_phoff`.
    pub fn program_headers(&self) -> &[ProgramHeader64] {
        &self.program_headers
    }

    /// Returns the dynamic section's entries before `DT_NULL`. An image
    /// without a `PT_DYNAMIC` segment has none.
    ///
    /// The values are as the section holds them. Once ld.so processes the
    /// object, glibc adds the load bias to the pointers in a writable dynamic
    /// section. A read-only one, such as the vDSO's, keeps the file's view.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `Elf64_Dyn` entries in the `PT_DYNAMIC` segment.
    pub fn dynamic_entries(&self) -> &[Dyn64] {
        &self.dynamic_entries
    }

    /// Reads the dynamic section that a `PT_DYNAMIC` program header points
    /// to. Returns its entries before `DT_NULL`, and the entries that the
    /// parser uses with their pointers resolved.
    fn read_dynamic(
        &self,
        reader: &impl ElfReader,
        program: &ProgramHeader64,
    ) -> Result<(Vec<Dyn64>, Dynamic), VmiError> {
        let count = checked_size(
            program.p_memsz / size_of::<Dyn64>() as u64,
            DYNAMIC_ENTRIES_MAX,
            "ELF dynamic section",
        )?;

        let writable = program.p_flags & PF_W != 0;
        let address = Va(self.bias.wrapping_add(program.p_vaddr));
        let bytes = read_bytes(reader, address, count * size_of::<Dyn64>())?;

        let mut entries = Vec::new();
        let mut dynamic = Dynamic::default();

        for bytes in bytes.as_chunks::<{ size_of::<Dyn64>() }>().0 {
            let entry = parse::<Dyn64>(bytes, "ELF dynamic entry")?;
            let value = entry.d_val;

            match entry.d_tag {
                DT_NULL => break,
                DT_HASH => dynamic.hash = Some(self.pointer(value, writable)?),
                DT_GNU_HASH => dynamic.gnu_hash = Some(self.pointer(value, writable)?),
                DT_SYMTAB => dynamic.symtab = Some(self.pointer(value, writable)?),
                DT_STRTAB => dynamic.strtab = Some(self.pointer(value, writable)?),
                DT_VERSYM => dynamic.versym = Some(self.pointer(value, writable)?),
                DT_RELA => dynamic.rela = Some(self.pointer(value, writable)?),
                DT_STRSZ => dynamic.strsz = Some(value),
                DT_SYMENT => dynamic.syment = Some(value),
                DT_SONAME => dynamic.soname = Some(value),
                DT_RELASZ => dynamic.relasz = Some(value),
                DT_RELAENT => dynamic.relaent = Some(value),
                _ => {}
            }

            entries.push(entry);
        }

        Ok((entries, dynamic))
    }

    /// Resolves a pointer of the dynamic section to an address in memory.
    ///
    /// A writable section can hold the pointer as an address in memory,
    /// once ld.so relocates it, or as an address in the file's view, before
    /// that. A read-only section always holds the file's view.
    fn pointer(&self, value: u64, writable: bool) -> Result<Va, VmiError> {
        let in_memory = self.base.0..self.base.0.saturating_add(self.span);
        if writable && in_memory.contains(&value) {
            return Ok(Va(value));
        }

        let in_file = self.start..self.start.saturating_add(self.span);
        if in_file.contains(&value) {
            return Ok(Va(self.bias.wrapping_add(value)));
        }

        Err(LinuxError::CorruptedImage("ELF dynamic pointer").into())
    }

    /// Returns the number of symbols in the symbol table, from a hash table.
    ///
    /// When an image has both tables, ld.so looks symbols up only through the
    /// GNU one. The SysV table's page can then be absent from the process's
    /// page tables, as in glibc 2.31's libc.
    fn symbol_count(&self, reader: &impl ElfReader) -> Result<usize, VmiError> {
        if let Some(gnu_hash) = self.dynamic.gnu_hash {
            return self.gnu_hash_count(reader, gnu_hash);
        }

        // The SysV hash table holds the count as `nchain`.
        match self.dynamic.hash {
            Some(hash) => {
                let count = read_u32(reader, hash + 4)?;
                checked_size(u64::from(count), SYMBOLS_MAX, "ELF symbol count")
            }
            None => Err(LinuxError::CorruptedImage("ELF hash table").into()),
        }
    }

    /// Returns the number of symbols from a GNU hash table.
    ///
    /// The bucket with the highest first symbol starts the last chain. Its
    /// end, the entry with the low bit set, is the last symbol.
    fn gnu_hash_count(&self, reader: &impl ElfReader, table: Va) -> Result<usize, VmiError> {
        let mut header = [0; 16];
        reader.read(table, &mut header)?;

        let (fields, _) = header.as_chunks::<4>();
        let bucket_count = checked_size(
            u64::from(u32::from_le_bytes(fields[0])),
            SYMBOLS_MAX,
            "ELF hash table",
        )?;
        let symbol_offset = u32::from_le_bytes(fields[1]);
        let bloom_words = u64::from(u32::from_le_bytes(fields[2]));

        let buckets = table + 16 + bloom_words * 8;
        let bytes = read_bytes(reader, buckets, bucket_count * 4)?;

        let last = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bucket| u32::from_le_bytes(*bucket))
            .max()
            .unwrap_or(0);

        if last < symbol_offset {
            return Ok(symbol_offset as usize);
        }

        let chains = buckets + bucket_count as u64 * 4;
        let mut index = last;

        loop {
            if index as usize >= SYMBOLS_MAX {
                return Err(LinuxError::CorruptedImage("ELF hash chain").into());
            }

            let value = read_u32(reader, chains + u64::from(index - symbol_offset) * 4)?;
            if value & 1 != 0 {
                return Ok(index as usize + 1);
            }

            index += 1;
        }
    }

    /// Reads the symbol table, the string table and the symbol versions.
    fn symbol_table(&self, reader: &impl ElfReader) -> Result<Option<SymbolTable>, VmiError> {
        let symtab = match self.dynamic.symtab {
            Some(symtab) => symtab,
            None => return Ok(None),
        };

        let (strtab, strsz) = match (self.dynamic.strtab, self.dynamic.strsz) {
            (Some(strtab), Some(strsz)) => (strtab, strsz),
            _ => return Err(LinuxError::CorruptedImage("ELF string table").into()),
        };

        let entry_size = match self.dynamic.syment {
            Some(syment) => checked_size(syment, 256, "ELF symbol size")?,
            None => size_of::<Sym64>(),
        };

        if entry_size < size_of::<Sym64>() {
            return Err(LinuxError::CorruptedImage("ELF symbol size").into());
        }

        let count = self.symbol_count(reader)?;
        let symbols = read_bytes(reader, symtab, count * entry_size)?;
        let strings = read_bytes(
            reader,
            strtab,
            checked_size(strsz, STRINGS_MAX, "ELF string table")?,
        )?;

        let versions = match self.dynamic.versym {
            Some(versym) => Some(read_bytes(reader, versym, count * 2)?),
            None => None,
        };

        Ok(Some(SymbolTable {
            symbols,
            entry_size,
            strings,
            versions,
        }))
    }

    /// Returns the exported symbols, with their addresses in memory.
    ///
    /// An export is a function or a data object that the image defines and
    /// other objects can see. Of the versions of a name, only the default
    /// one is kept. An image without a dynamic symbol table has none.
    pub(crate) fn exports(
        &self,
        reader: &impl ElfReader,
    ) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let table = match self.symbol_table(reader)? {
            Some(table) => table,
            None => return Ok(Vec::new()),
        };

        let mut exports = Vec::new();

        for index in 0..table.len() {
            let (symbol, name) = table.get(index)?;

            if !is_export(&symbol) || table.is_hidden(index) || name.is_empty() {
                continue;
            }

            exports.push(VmiOsImageSymbol {
                name: String::from_utf8_lossy(name).into_owned(),
                address: Va(self.bias.wrapping_add(symbol.st_value)),
            });
        }

        Ok(exports)
    }

    /// Returns the object's name (`DT_SONAME`), if it has one.
    pub(crate) fn soname(&self, reader: &impl ElfReader) -> Result<Option<String>, VmiError> {
        let offset = match self.dynamic.soname {
            Some(offset) => offset,
            None => return Ok(None),
        };

        let (strtab, strsz) = match (self.dynamic.strtab, self.dynamic.strsz) {
            (Some(strtab), Some(strsz)) if offset < strsz => (strtab, strsz),
            _ => return Err(LinuxError::CorruptedImage("ELF object name").into()),
        };

        let length = checked_size(strsz - offset, STRINGS_MAX, "ELF string table")?;
        let bytes = read_bytes(reader, strtab + offset, length.min(SONAME_MAX))?;

        match memchr::memchr(0, &bytes) {
            Some(end) => Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned())),
            None => Err(LinuxError::CorruptedImage("ELF object name").into()),
        }
    }

    /// Returns the GNU build-id, if the image has one.
    ///
    /// The build-id is the descriptor of the first `NT_GNU_BUILD_ID` note
    /// with the name `GNU` in the `PT_NOTE` segments.
    pub(crate) fn build_id(&self, reader: &impl ElfReader) -> Result<Option<BuildId>, VmiError> {
        for program in &self.program_headers {
            if program.p_type != PT_NOTE {
                continue;
            }

            let address = Va(self.bias.wrapping_add(program.p_vaddr));
            let align = note::segment_alignment(program.p_align);

            if let Some(build_id) = read_build_id(reader, address, program.p_memsz, align)? {
                return Ok(Some(build_id));
            }
        }

        Ok(None)
    }

    /// Returns the address of the slot into which ld.so writes a TLS
    /// variable's offset from the thread pointer.
    ///
    /// The slot is the target of the `R_X86_64_TPOFF64` relocation that
    /// names the variable, or names symbol 0 with the variable's offset as
    /// its addend. Returns `None` if the image has no such variable or no
    /// such relocation.
    pub(crate) fn tls_offset_slot(
        &self,
        reader: &impl ElfReader,
        name: &str,
    ) -> Result<Option<Va>, VmiError> {
        let table = match self.symbol_table(reader)? {
            Some(table) => table,
            None => return Ok(None),
        };

        let mut variable = None;

        for index in 0..table.len() {
            let (symbol, symbol_name) = table.get(index)?;

            if symbol.st_info & 0x0f == STT_TLS
                && symbol.st_shndx != SHN_UNDEF
                && symbol_name == name.as_bytes()
            {
                variable = Some((index as u64, symbol.st_value));
                break;
            }
        }

        let (index, value) = match variable {
            Some(variable) => variable,
            None => return Ok(None),
        };

        let (rela, relasz) = match (self.dynamic.rela, self.dynamic.relasz) {
            (Some(rela), Some(relasz)) => (rela, relasz),
            _ => return Ok(None),
        };

        let entry_size = match self.dynamic.relaent {
            Some(relaent) => checked_size(relaent, 256, "ELF relocation size")?,
            None => size_of::<Rela64>(),
        };

        if entry_size < size_of::<Rela64>() {
            return Err(LinuxError::CorruptedImage("ELF relocation size").into());
        }

        let count = checked_size(
            relasz / entry_size as u64,
            RELOCATIONS_MAX,
            "ELF relocations",
        )?;
        let bytes = read_bytes(reader, rela, count * entry_size)?;

        for bytes in bytes.chunks_exact(entry_size) {
            let relocation = parse::<Rela64>(bytes, "ELF relocation")?;
            let kind = (relocation.r_info & 0xffff_ffff) as u32;
            let symbol = relocation.r_info >> 32;

            if kind != R_X86_64_TPOFF64 {
                continue;
            }

            if symbol == index || (symbol == 0 && relocation.r_addend as u64 == value) {
                return Ok(Some(Va(self.bias.wrapping_add(relocation.r_offset))));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use zerocopy::IntoBytes as _;

    use super::{
        note::tests::{BUILD_ID, push_note},
        *,
    };

    /// Where the tests load their image.
    const BASE: u64 = 0x7f12_3450_0000;

    /// File offsets in the test image.
    const NOTES: u64 = 0x0200;
    const DYNAMIC: u64 = 0x1000;
    const GNU_HASH: u64 = 0x1200;
    const HASH: u64 = 0x1400;
    const SYMTAB: u64 = 0x1600;
    const STRTAB: u64 = 0x1a00;
    const VERSYM: u64 = 0x1c00;
    const RELA: u64 = 0x1d00;

    /// Guest memory with one image.
    struct Memory {
        /// Address of the first byte.
        base: u64,

        /// The bytes.
        bytes: Vec<u8>,

        /// Offsets whose page is absent, which reads cannot reach.
        absent: Range<u64>,
    }

    impl Memory {
        /// Writes bytes at an offset.
        fn write(&mut self, offset: u64, bytes: &[u8]) {
            let offset = offset as usize;
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    impl ElfReader for Memory {
        fn read(&self, va: Va, buffer: &mut [u8]) -> Result<(), VmiError> {
            let offset = va.0.wrapping_sub(self.base);
            if offset < self.absent.end && self.absent.start < offset + buffer.len() as u64 {
                return Err(VmiError::Other("absent page"));
            }

            let start = offset as usize;

            match self.bytes.get(start..start.saturating_add(buffer.len())) {
                Some(bytes) => {
                    buffer.copy_from_slice(bytes);
                    Ok(())
                }
                None => Err(VmiError::Other("outside the image")),
            }
        }
    }

    /// How the test image is built.
    #[derive(Clone, Copy)]
    struct Layout {
        /// The class and the machine.
        class: u8,
        machine: u16,

        /// Whether ld.so already added the bias to the dynamic pointers.
        relocated: bool,

        /// Whether the dynamic segment is writable.
        writable: bool,

        /// Whether the image has a GNU hash table.
        gnu_hash: bool,

        /// Whether the image has a SysV hash table.
        sysv_hash: bool,

        /// Whether the TPOFF relocation names `errno` instead of symbol 0.
        tpoff_names_symbol: bool,

        /// The `p_align` of a `PT_NOTE` segment with a build-id, or `None`
        /// for an image without notes.
        note_align: Option<u64>,
    }

    impl Default for Layout {
        fn default() -> Self {
            Self {
                class: ELFCLASS64,
                machine: EM_X86_64,
                relocated: true,
                writable: true,
                gnu_hash: true,
                sysv_hash: false,
                tpoff_names_symbol: false,
                note_align: None,
            }
        }
    }

    /// A symbol of the test image: name, binding, type, visibility,
    /// section, value and whether its version is hidden.
    type TestSymbol = (&'static str, u8, u8, u8, u16, u64, bool);

    /// The symbols of the test image, after the null symbol.
    const SYMBOLS: &[TestSymbol] = &[
        (
            "printf",
            STB_GLOBAL,
            STT_FUNC,
            STV_DEFAULT,
            1,
            0x0500,
            false,
        ),
        (
            "environ",
            STB_WEAK,
            STT_OBJECT,
            STV_DEFAULT,
            2,
            0x2400,
            false,
        ),
        (
            "memcpy",
            STB_GLOBAL,
            STT_GNU_IFUNC,
            STV_PROTECTED,
            1,
            0x0600,
            false,
        ),
        ("errno", STB_GLOBAL, STT_TLS, STV_DEFAULT, 3, 0x28, false),
        ("local_helper", 0, STT_FUNC, STV_DEFAULT, 1, 0x0700, false),
        (
            "malloc",
            STB_GLOBAL,
            STT_FUNC,
            STV_DEFAULT,
            SHN_UNDEF,
            0,
            false,
        ),
        (
            "GLIBC_2.2.5",
            STB_GLOBAL,
            STT_OBJECT,
            STV_DEFAULT,
            SHN_ABS,
            0,
            false,
        ),
        ("hidden_helper", STB_GLOBAL, STT_FUNC, 2, 1, 0x0800, false),
        ("memcpy", STB_GLOBAL, STT_FUNC, STV_DEFAULT, 1, 0x0900, true),
    ];

    /// Builds the test image at `BASE`.
    fn image(layout: Layout) -> Memory {
        let mut memory = Memory {
            base: BASE,
            bytes: vec![0; 0x3000],
            absent: 0..0,
        };

        let pointer = |offset: u64| {
            if layout.relocated {
                BASE + offset
            }
            else {
                offset
            }
        };

        let header = FileHeader64 {
            e_ident: Ident {
                magic: ELFMAG,
                class: layout.class,
                data: ELFDATA2LSB,
                version: 1,
                os_abi: 0,
                abi_version: 0,
                padding: [0; 7],
            },
            e_type: 3,
            e_machine: layout.machine,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0x40,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: if layout.note_align.is_some() { 3 } else { 2 },
            e_shentsize: 64,
            e_shnum: 0,
            e_shstrndx: 0,
        };
        memory.write(0, header.as_bytes());

        // One segment for the whole file, with `.bss` up to 0x2800.
        let load = ProgramHeader64 {
            p_type: PT_LOAD,
            p_flags: 6,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0x2000,
            p_memsz: 0x2800,
            p_align: 0x1000,
        };
        let dynamic = ProgramHeader64 {
            p_type: PT_DYNAMIC,
            p_flags: if layout.writable { 6 } else { 4 },
            p_offset: DYNAMIC,
            p_vaddr: DYNAMIC,
            p_paddr: DYNAMIC,
            p_filesz: 16 * 16,
            p_memsz: 16 * 16,
            p_align: 8,
        };
        memory.write(0x40, load.as_bytes());
        memory.write(0x40 + 56, dynamic.as_bytes());

        // Another note comes before the build-id, and both use the segment's
        // alignment.
        if let Some(p_align) = layout.note_align {
            let align = p_align as usize;
            let mut notes = Vec::new();
            push_note(&mut notes, b"GNU\0", 5, &[0xaa; 12], align);
            push_note(&mut notes, b"GNU\0", NT_GNU_BUILD_ID, &BUILD_ID, align);
            memory.write(NOTES, &notes);

            let note = ProgramHeader64 {
                p_type: PT_NOTE,
                p_flags: 4,
                p_offset: NOTES,
                p_vaddr: NOTES,
                p_paddr: NOTES,
                p_filesz: notes.len() as u64,
                p_memsz: notes.len() as u64,
                p_align,
            };
            memory.write(0x40 + 2 * 56, note.as_bytes());
        }

        // The string table: the object's name first, then the symbols.
        let mut strings = vec![0u8];
        let soname = strings.len() as u64;
        strings.extend_from_slice(b"libtest.so.1\0");

        let mut name_offsets = Vec::new();
        for (name, ..) in SYMBOLS {
            name_offsets.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        memory.write(STRTAB, &strings);

        // The symbols and their versions, after the null symbol.
        let count = SYMBOLS.len() as u32 + 1;
        for (index, (_, binding, kind, visibility, section, value, hidden)) in
            SYMBOLS.iter().enumerate()
        {
            let symbol = Sym64 {
                st_name: name_offsets[index],
                st_info: (binding << 4) | kind,
                st_other: *visibility,
                st_shndx: *section,
                st_value: *value,
                st_size: 0,
            };
            let index = index as u64 + 1;
            memory.write(SYMTAB + index * 24, symbol.as_bytes());

            let version: u16 = if *hidden { VERSYM_HIDDEN | 2 } else { 2 };
            memory.write(VERSYM + index * 2, &version.to_le_bytes());
        }

        // A GNU hash table with two buckets, whose last chain ends at the
        // last symbol, and a SysV one that holds the count.
        let gnu_hash = [2u32, 1, 1, 6];
        for (index, value) in gnu_hash.iter().enumerate() {
            memory.write(GNU_HASH + index as u64 * 4, &value.to_le_bytes());
        }
        let buckets = GNU_HASH + 16 + 8;
        memory.write(buckets, &1u32.to_le_bytes());
        memory.write(buckets + 4, &5u32.to_le_bytes());
        let chains = buckets + 8;
        for symbol in 1..count {
            let value: u32 = if symbol == 4 || symbol == count - 1 {
                1
            }
            else {
                0
            };
            memory.write(chains + u64::from(symbol - 1) * 4, &value.to_le_bytes());
        }

        memory.write(HASH, &1u32.to_le_bytes());
        memory.write(HASH + 4, &count.to_le_bytes());

        // A relative relocation, then the TPOFF one for `errno`.
        let (tpoff_symbol, tpoff_addend) = if layout.tpoff_names_symbol {
            (4u64, 0)
        }
        else {
            (0, 0x28)
        };
        let relocations = [
            Rela64 {
                r_offset: 0x2000,
                r_info: 8,
                r_addend: 0x500,
            },
            Rela64 {
                r_offset: 0x2100,
                r_info: (tpoff_symbol << 32) | u64::from(R_X86_64_TPOFF64),
                r_addend: tpoff_addend,
            },
        ];
        for (index, relocation) in relocations.iter().enumerate() {
            memory.write(RELA + index as u64 * 24, relocation.as_bytes());
        }

        let mut entries = Vec::new();
        if layout.gnu_hash {
            entries.push((DT_GNU_HASH, pointer(GNU_HASH)));
        }
        if layout.sysv_hash {
            entries.push((DT_HASH, pointer(HASH)));
        }
        entries.extend([
            (DT_SYMTAB, pointer(SYMTAB)),
            (DT_STRTAB, pointer(STRTAB)),
            (DT_STRSZ, strings.len() as u64),
            (DT_SYMENT, 24),
            (DT_VERSYM, pointer(VERSYM)),
            (DT_SONAME, soname),
            (DT_RELA, pointer(RELA)),
            (DT_RELASZ, 2 * 24),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ]);
        for (index, (tag, value)) in entries.iter().enumerate() {
            let entry = Dyn64 {
                d_tag: *tag,
                d_val: *value,
            };
            memory.write(DYNAMIC + index as u64 * 16, entry.as_bytes());
        }

        memory
    }

    /// Returns the exports as names and offsets from the base.
    fn exports(memory: &Memory) -> Result<Vec<(String, u64)>, VmiError> {
        let image = ElfImage::parse(memory, Va(BASE))?;

        Ok(image
            .exports(memory)?
            .into_iter()
            .map(|symbol| (symbol.name, symbol.address.0 - BASE))
            .collect())
    }

    /// The exports of the test image, as names and offsets from the base.
    fn expected_exports() -> Vec<(String, u64)> {
        vec![
            (String::from("printf"), 0x0500),
            (String::from("environ"), 0x2400),
            (String::from("memcpy"), 0x0600),
        ]
    }

    #[test]
    fn exports_keep_visible_definitions_and_default_versions() -> Result<(), VmiError> {
        let memory = image(Layout::default());

        assert_eq!(exports(&memory)?, expected_exports());
        Ok(())
    }

    #[test]
    fn exports_before_relocation_add_the_bias() -> Result<(), VmiError> {
        let memory = image(Layout {
            relocated: false,
            ..Layout::default()
        });

        assert_eq!(exports(&memory)?, expected_exports());
        Ok(())
    }

    #[test]
    fn read_only_dynamic_section_holds_offsets() -> Result<(), VmiError> {
        let memory = image(Layout {
            relocated: false,
            writable: false,
            gnu_hash: false,
            sysv_hash: true,
            ..Layout::default()
        });

        assert_eq!(exports(&memory)?, expected_exports());
        Ok(())
    }

    #[test]
    fn gnu_hash_table_comes_before_the_sysv_one() -> Result<(), VmiError> {
        // With both tables, ld.so reads only the GNU one, and the page of the
        // SysV table can be absent.
        let mut memory = image(Layout {
            sysv_hash: true,
            ..Layout::default()
        });
        memory.absent = HASH..HASH + 8;

        assert_eq!(exports(&memory)?, expected_exports());
        Ok(())
    }

    #[test]
    fn read_only_dynamic_section_rejects_addresses() {
        let memory = image(Layout {
            writable: false,
            ..Layout::default()
        });

        assert!(ElfImage::parse(&memory, Va(BASE)).is_err());
    }

    #[test]
    fn size_covers_bss() -> Result<(), VmiError> {
        let memory = image(Layout::default());

        assert_eq!(ElfImage::parse(&memory, Va(BASE))?.size(), 0x3000);
        Ok(())
    }

    #[test]
    fn soname_comes_from_the_string_table() -> Result<(), VmiError> {
        let memory = image(Layout::default());
        let image = ElfImage::parse(&memory, Va(BASE))?;

        assert_eq!(image.soname(&memory)?, Some(String::from("libtest.so.1")));
        Ok(())
    }

    #[test]
    fn tls_slot_matches_the_addend_of_symbol_zero() -> Result<(), VmiError> {
        let memory = image(Layout::default());
        let image = ElfImage::parse(&memory, Va(BASE))?;

        assert_eq!(
            image.tls_offset_slot(&memory, "errno")?,
            Some(Va(BASE + 0x2100))
        );
        assert_eq!(image.tls_offset_slot(&memory, "printf")?, None);
        Ok(())
    }

    #[test]
    fn tls_slot_matches_the_symbol_index() -> Result<(), VmiError> {
        let memory = image(Layout {
            tpoff_names_symbol: true,
            ..Layout::default()
        });
        let image = ElfImage::parse(&memory, Va(BASE))?;

        assert_eq!(
            image.tls_offset_slot(&memory, "errno")?,
            Some(Va(BASE + 0x2100))
        );
        Ok(())
    }

    #[test]
    fn architecture_comes_from_class_and_machine() -> Result<(), VmiError> {
        let amd64 = image(Layout::default());
        let x86 = image(Layout {
            class: ELFCLASS32,
            machine: EM_386,
            ..Layout::default()
        });
        let arm64 = image(Layout {
            machine: 183,
            ..Layout::default()
        });

        assert_eq!(
            architecture(&amd64, Va(BASE))?,
            Some(VmiOsImageArchitecture::Amd64)
        );
        assert_eq!(
            architecture(&x86, Va(BASE))?,
            Some(VmiOsImageArchitecture::X86)
        );
        assert_eq!(architecture(&arm64, Va(BASE))?, None);
        Ok(())
    }

    #[test]
    fn elf32_images_are_not_parsed() {
        let memory = image(Layout {
            class: ELFCLASS32,
            machine: EM_386,
            ..Layout::default()
        });

        assert!(matches!(
            ElfImage::parse(&memory, Va(BASE)),
            Err(VmiError::NotSupported)
        ));
    }

    #[test]
    fn missing_magic_is_an_error() {
        let mut memory = image(Layout::default());
        memory.write(0, b"\x7fXYZ");

        assert!(architecture(&memory, Va(BASE)).is_err());
        assert!(ElfImage::parse(&memory, Va(BASE)).is_err());
    }

    #[test]
    fn build_id_comes_from_the_note_segment() -> Result<(), VmiError> {
        for note_align in [4, 8] {
            let memory = image(Layout {
                note_align: Some(note_align),
                ..Layout::default()
            });
            let image = ElfImage::parse(&memory, Va(BASE))?;

            let build_id = image.build_id(&memory)?;
            assert_eq!(
                build_id.as_ref().map(BuildId::as_bytes),
                Some(&BUILD_ID[..]),
                "p_align {note_align}"
            );
        }
        Ok(())
    }

    #[test]
    fn image_without_notes_has_no_build_id() -> Result<(), VmiError> {
        let memory = image(Layout::default());
        let image = ElfImage::parse(&memory, Va(BASE))?;

        assert_eq!(image.build_id(&memory)?, None);
        Ok(())
    }

    #[test]
    fn oversized_note_segment_is_an_error() -> Result<(), VmiError> {
        let mut memory = image(Layout {
            note_align: Some(4),
            ..Layout::default()
        });

        // These bytes hold `p_memsz` in the third program header.
        memory.write(0x40 + 2 * 56 + 40, &(1u64 << 20).to_le_bytes());
        let image = ElfImage::parse(&memory, Va(BASE))?;

        // The size check fails before a read outside the test image, which
        // would give `VmiError::Other`.
        assert!(matches!(image.build_id(&memory), Err(VmiError::Os(_))));
        Ok(())
    }
}
