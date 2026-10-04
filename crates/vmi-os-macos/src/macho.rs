//! Parsing of 64-bit Mach-O headers and load commands.
//!
//! The layouts follow `<mach-o/loader.h>` and `<mach-o/nlist.h>`. All values
//! are little-endian.

use vmi_core::os::VmiOsImageArchitecture;

use crate::MacOsError;

/// Magic number of a 64-bit Mach-O header.
pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;

/// File type of a kernel collection, a set of Mach-O images in one file.
pub(crate) const MH_FILESET: u32 = 0xc;

/// Load command describing the symbol table.
pub(crate) const LC_SYMTAB: u32 = 0x2;

/// Load command describing a 64-bit segment.
pub(crate) const LC_SEGMENT_64: u32 = 0x19;

/// Load command carrying the image UUID.
pub(crate) const LC_UUID: u32 = 0x1b;

/// Load command describing one image of a kernel collection.
pub(crate) const LC_FILESET_ENTRY: u32 = 0x8000_0035;

/// CPU type of 32-bit Intel code.
pub(crate) const CPU_TYPE_X86: i32 = 0x7;

/// CPU type of 64-bit Intel code.
pub(crate) const CPU_TYPE_X86_64: i32 = 0x0100_0007;

/// CPU type of 64-bit ARM code.
pub(crate) const CPU_TYPE_ARM64: i32 = 0x0100_000c;

/// Size of `struct mach_header_64`, in bytes.
pub(crate) const MACH_HEADER_64_SIZE: usize = 32;

/// Upper bound on `sizeofcmds` accepted from guest memory, in bytes.
pub(crate) const MAX_LOAD_COMMANDS_SIZE: u32 = 0x10_0000;

/// Size of `struct nlist_64`, in bytes.
pub(crate) const NLIST_64_SIZE: usize = 16;

/// Mask of the symbol type bits in `nlist_64.n_type`.
const N_TYPE: u8 = 0x0e;

/// Symbol type of a symbol defined in a section.
const N_SECT: u8 = 0x0e;

/// Flag of an external symbol in `nlist_64.n_type`.
const N_EXT: u8 = 0x01;

/// Mask of the debugging (stab) bits in `nlist_64.n_type`.
const N_STAB: u8 = 0xe0;

/// Reads a little-endian `u32` at `offset`, or `None` when out of bounds.
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Reads a little-endian `u64` at `offset`, or `None` when out of bounds.
pub(crate) fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Decodes a fixed-size, NUL-padded C string.
pub(crate) fn fixed_string(data: &[u8]) -> String {
    let end = memchr::memchr(0, data).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Decodes a NUL-terminated C string at `offset`, or `None` when the offset
/// is out of bounds.
fn c_string(data: &[u8], offset: usize) -> Option<String> {
    data.get(offset..).map(fixed_string)
}

/// Returns the image architecture of a Mach-O CPU type.
pub(crate) fn architecture_from_cpu_type(cpu_type: i32) -> Option<VmiOsImageArchitecture> {
    match cpu_type {
        CPU_TYPE_ARM64 => Some(VmiOsImageArchitecture::Arm64),
        CPU_TYPE_X86_64 => Some(VmiOsImageArchitecture::Amd64),
        CPU_TYPE_X86 => Some(VmiOsImageArchitecture::X86),
        _ => None,
    }
}

/// The fields of `struct mach_header_64` used by this crate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MachHeader {
    /// CPU type of the image, `cputype`.
    pub cpu_type: i32,

    /// Kind of image, `filetype`.
    pub file_type: u32,

    /// Number of load commands, `ncmds`.
    pub number_of_commands: u32,

    /// Total size of the load commands in bytes, `sizeofcmds`.
    pub size_of_commands: u32,
}

impl MachHeader {
    /// Parses a 64-bit Mach-O header from the start of `data`.
    pub fn parse(data: &[u8]) -> Result<Self, MacOsError> {
        if read_u32(data, 0) != Some(MH_MAGIC_64) {
            return Err(MacOsError::InvalidMachO("bad magic"));
        }

        match (
            read_u32(data, 4),
            read_u32(data, 12),
            read_u32(data, 16),
            read_u32(data, 20),
        ) {
            (Some(cpu_type), Some(file_type), Some(number_of_commands), Some(size_of_commands)) => {
                Ok(Self {
                    cpu_type: cpu_type as i32,
                    file_type,
                    number_of_commands,
                    size_of_commands,
                })
            }
            _ => Err(MacOsError::InvalidMachO("truncated header")),
        }
    }

    /// Returns the size of the header plus its load commands, in bytes.
    pub fn total_size(&self) -> Result<usize, MacOsError> {
        if self.size_of_commands > MAX_LOAD_COMMANDS_SIZE {
            return Err(MacOsError::InvalidMachO("load commands too large"));
        }

        Ok(MACH_HEADER_64_SIZE + self.size_of_commands as usize)
    }
}

/// A single load command.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadCommand<'a> {
    /// Command type, `cmd`.
    pub command: u32,

    /// Bytes of the command, starting with `cmd` and `cmdsize`.
    pub data: &'a [u8],
}

/// A `LC_SEGMENT_64` load command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachSegment {
    /// Segment name, `segname`.
    pub name: String,

    /// Virtual address of the segment, `vmaddr`.
    pub vm_address: u64,

    /// Virtual size of the segment, `vmsize`.
    pub vm_size: u64,

    /// File offset of the segment, `fileoff`.
    pub file_offset: u64,

    /// Size of the segment in the file, `filesize`.
    pub file_size: u64,
}

/// A `LC_FILESET_ENTRY` load command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesetEntry {
    /// Identifier of the image, `entry_id`.
    pub name: String,

    /// Virtual address of the image header, `vmaddr`.
    pub vm_address: u64,
}

/// A `LC_SYMTAB` load command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Symtab {
    /// File offset of the `nlist_64` array, `symoff`.
    pub symbol_offset: u32,

    /// Number of symbols, `nsyms`.
    pub number_of_symbols: u32,

    /// File offset of the string table, `stroff`.
    pub string_offset: u32,

    /// Size of the string table in bytes, `strsize`.
    pub string_size: u32,
}

/// A 64-bit Mach-O header followed by its load commands.
pub(crate) struct MachO<'a> {
    /// Parsed header.
    header: MachHeader,

    /// Bytes of the header and the load commands.
    data: &'a [u8],
}

impl<'a> MachO<'a> {
    /// Parses a Mach-O image from `data`, which must hold the header and all
    /// load commands.
    pub fn parse(data: &'a [u8]) -> Result<Self, MacOsError> {
        let header = MachHeader::parse(data)?;
        let total_size = header.total_size()?;

        let data = match data.get(..total_size) {
            Some(data) => data,
            None => return Err(MacOsError::InvalidMachO("truncated load commands")),
        };

        Ok(Self { header, data })
    }

    /// Returns the parsed header.
    pub fn header(&self) -> &MachHeader {
        &self.header
    }

    /// Returns the load commands.
    ///
    /// Iteration stops with an error at the first command whose size is
    /// smaller than its own header or exceeds the load command area.
    pub fn load_commands(
        &self,
    ) -> impl Iterator<Item = Result<LoadCommand<'a>, MacOsError>> + use<'a> {
        let data = self.data;
        let mut offset = MACH_HEADER_64_SIZE;
        let mut remaining = self.header.number_of_commands;

        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }

            remaining -= 1;

            let command = read_u32(data, offset);
            let size = read_u32(data, offset + 4);

            let (command, size) = match (command, size) {
                (Some(command), Some(size)) if size >= 8 => (command, size as usize),
                _ => {
                    remaining = 0;
                    return Some(Err(MacOsError::InvalidMachO("malformed load command")));
                }
            };

            let command_data = match data.get(offset..offset + size) {
                Some(command_data) => command_data,
                None => {
                    remaining = 0;
                    return Some(Err(MacOsError::InvalidMachO("load command out of bounds")));
                }
            };

            offset += size;

            Some(Ok(LoadCommand {
                command,
                data: command_data,
            }))
        })
    }

    /// Returns the `LC_SEGMENT_64` commands in load command order.
    pub fn segments(&self) -> Result<Vec<MachSegment>, MacOsError> {
        let mut result = Vec::new();

        for command in self.load_commands() {
            let command = command?;
            if command.command != LC_SEGMENT_64 {
                continue;
            }

            let data = command.data;
            match (
                data.get(8..24),
                read_u64(data, 24),
                read_u64(data, 32),
                read_u64(data, 40),
                read_u64(data, 48),
            ) {
                (
                    Some(name),
                    Some(vm_address),
                    Some(vm_size),
                    Some(file_offset),
                    Some(file_size),
                ) => {
                    result.push(MachSegment {
                        name: fixed_string(name),
                        vm_address,
                        vm_size,
                        file_offset,
                        file_size,
                    });
                }
                _ => return Err(MacOsError::InvalidMachO("truncated segment command")),
            }
        }

        Ok(result)
    }

    /// Returns the UUID of the image, if it has a `LC_UUID` command.
    pub fn uuid(&self) -> Result<Option<[u8; 16]>, MacOsError> {
        for command in self.load_commands() {
            let command = command?;
            if command.command != LC_UUID {
                continue;
            }

            return match command.data.get(8..24) {
                Some(uuid) => Ok(uuid.try_into().ok()),
                None => Err(MacOsError::InvalidMachO("truncated UUID command")),
            };
        }

        Ok(None)
    }

    /// Returns the `LC_FILESET_ENTRY` commands of a kernel collection.
    pub fn fileset_entries(&self) -> Result<Vec<FilesetEntry>, MacOsError> {
        let mut result = Vec::new();

        for command in self.load_commands() {
            let command = command?;
            if command.command != LC_FILESET_ENTRY {
                continue;
            }

            let data = command.data;
            let name =
                read_u32(data, 24).and_then(|name_offset| c_string(data, name_offset as usize));

            match (read_u64(data, 8), name) {
                (Some(vm_address), Some(name)) => {
                    result.push(FilesetEntry { name, vm_address });
                }
                _ => return Err(MacOsError::InvalidMachO("truncated fileset entry")),
            }
        }

        Ok(result)
    }

    /// Returns the `LC_SYMTAB` command, if present.
    pub fn symtab(&self) -> Result<Option<Symtab>, MacOsError> {
        for command in self.load_commands() {
            let command = command?;
            if command.command != LC_SYMTAB {
                continue;
            }

            let data = command.data;
            return match (
                read_u32(data, 8),
                read_u32(data, 12),
                read_u32(data, 16),
                read_u32(data, 20),
            ) {
                (
                    Some(symbol_offset),
                    Some(number_of_symbols),
                    Some(string_offset),
                    Some(string_size),
                ) => Ok(Some(Symtab {
                    symbol_offset,
                    number_of_symbols,
                    string_offset,
                    string_size,
                })),
                _ => Err(MacOsError::InvalidMachO("truncated symtab command")),
            };
        }

        Ok(None)
    }
}

/// Returns the external symbols defined in a section, as `(name, n_value)`
/// pairs.
///
/// `symbols` holds the `nlist_64` array and `strings` the string table.
/// Entries whose name lies outside the string table are skipped.
pub(crate) fn exported_symbols(symbols: &[u8], strings: &[u8]) -> Vec<(String, u64)> {
    symbols
        .chunks_exact(NLIST_64_SIZE)
        .filter_map(|nlist| {
            let name_offset = read_u32(nlist, 0)? as usize;
            let symbol_type = nlist[4];
            let value = read_u64(nlist, 8)?;

            if symbol_type & N_STAB != 0
                || symbol_type & N_EXT == 0
                || symbol_type & N_TYPE != N_SECT
            {
                return None;
            }

            let name = c_string(strings, name_offset)?;
            if name.is_empty() {
                return None;
            }

            Some((name, value))
        })
        .collect()
}

/// Returns the size of the run of contiguous segments that starts at the
/// segment containing `start`.
///
/// The segments of an image in the dyld shared cache are scattered across
/// the cache, so only the segments adjacent to the header count towards the
/// image size. `segments` holds `(address, size)` pairs at runtime addresses.
/// A segment that extends past the end of the address space ends the run at
/// the end of the address space.
pub(crate) fn contiguous_size(segments: &[(u64, u64)], start: u64) -> u64 {
    let mut segments = segments
        .iter()
        .copied()
        .filter(|&(_, size)| size != 0)
        .collect::<Vec<_>>();
    segments.sort_unstable();

    let mut end = match segments
        .iter()
        .find(|&&(address, size)| start >= address && start - address < size)
    {
        Some(&(address, size)) => address.saturating_add(size),
        None => return 0,
    };

    for &(address, size) in &segments {
        if address == end {
            end = end.saturating_add(size);
        }
    }

    end - start
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a Mach-O image from a file type and raw load commands.
    fn image(file_type: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let size_of_commands = commands.iter().map(Vec::len).sum::<usize>() as u32;

        let mut data = Vec::new();
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        data.extend_from_slice(&(CPU_TYPE_ARM64 as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&file_type.to_le_bytes());
        data.extend_from_slice(&(commands.len() as u32).to_le_bytes());
        data.extend_from_slice(&size_of_commands.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        for command in commands {
            data.extend_from_slice(command);
        }

        data
    }

    /// Builds a load command from its type and body.
    fn command(command: u32, body: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&command.to_le_bytes());
        data.extend_from_slice(&(8 + body.len() as u32).to_le_bytes());
        data.extend_from_slice(body);
        data
    }

    /// Builds a `LC_SEGMENT_64` command.
    fn segment(name: &str, vm_address: u64, vm_size: u64) -> Vec<u8> {
        let mut body = [0u8; 64];
        body[..name.len()].copy_from_slice(name.as_bytes());
        body[16..24].copy_from_slice(&vm_address.to_le_bytes());
        body[24..32].copy_from_slice(&vm_size.to_le_bytes());
        body[32..40].copy_from_slice(&0x4000u64.to_le_bytes());
        body[40..48].copy_from_slice(&vm_size.to_le_bytes());
        command(LC_SEGMENT_64, &body)
    }

    /// Builds a `LC_FILESET_ENTRY` command with the name stored after the
    /// fixed part.
    fn fileset_entry(name: &str, vm_address: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&vm_address.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&32u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&[0; 7]);
        command(LC_FILESET_ENTRY, &body)
    }

    #[test]
    fn parses_fileset_entries() {
        let data = image(
            MH_FILESET,
            &[
                segment("__TEXT", 0xfffffe0007004000, 0x4000),
                fileset_entry("com.apple.driver.Example", 0xfffffe0008000000),
                fileset_entry("com.apple.kernel", 0xfffffe0007008000),
            ],
        );

        let macho = MachO::parse(&data).unwrap();
        assert_eq!(macho.header().file_type, MH_FILESET);
        assert_eq!(
            macho.fileset_entries().unwrap(),
            [
                FilesetEntry {
                    name: String::from("com.apple.driver.Example"),
                    vm_address: 0xfffffe0008000000,
                },
                FilesetEntry {
                    name: String::from("com.apple.kernel"),
                    vm_address: 0xfffffe0007008000,
                },
            ]
        );
    }

    #[test]
    fn parses_segments_and_uuid() {
        let uuid = *b"0123456789abcdef";
        let data = image(
            2,
            &[
                segment("__TEXT", 0xfffffe0007004000, 0x4000),
                command(LC_UUID, &uuid),
                segment("__DATA", 0xfffffe0007008000, 0x8000),
            ],
        );

        let macho = MachO::parse(&data).unwrap();
        assert_eq!(macho.header().cpu_type, CPU_TYPE_ARM64);
        assert_eq!(macho.uuid().unwrap(), Some(uuid));

        let segments = macho.segments().unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].name, "__TEXT");
        assert_eq!(segments[1].name, "__DATA");
        assert_eq!(segments[1].vm_address, 0xfffffe0007008000);
        assert_eq!(segments[1].vm_size, 0x8000);
        assert_eq!(segments[1].file_offset, 0x4000);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = image(2, &[]);
        data[0] = 0;
        assert!(MachO::parse(&data).is_err());
    }

    #[test]
    fn rejects_truncated_load_commands() {
        let data = image(2, &[segment("__TEXT", 0, 0x4000)]);
        assert!(MachO::parse(&data[..data.len() - 1]).is_err());
    }

    #[test]
    fn stops_at_undersized_load_command() {
        let mut data = image(2, &[segment("__TEXT", 0, 0x4000)]);
        // Shrink `cmdsize` below the size of the command header.
        data[MACH_HEADER_64_SIZE + 4..MACH_HEADER_64_SIZE + 8].copy_from_slice(&4u32.to_le_bytes());

        let macho = MachO::parse(&data).unwrap();
        let commands = macho.load_commands().collect::<Vec<_>>();
        assert_eq!(commands.len(), 1);
        assert!(commands[0].is_err());
        assert!(macho.segments().is_err());
    }

    #[test]
    fn stops_at_overlong_load_command() {
        let mut data = image(2, &[segment("__TEXT", 0, 0x4000)]);
        data[MACH_HEADER_64_SIZE + 4..MACH_HEADER_64_SIZE + 8]
            .copy_from_slice(&0x1000u32.to_le_bytes());

        let macho = MachO::parse(&data).unwrap();
        assert!(macho.segments().is_err());
    }

    #[test]
    fn filters_exported_symbols() {
        let strings = b"\0_exported\0_local\0_undefined\0";

        let nlist = |name: u32, symbol_type: u8, value: u64| {
            let mut entry = Vec::new();
            entry.extend_from_slice(&name.to_le_bytes());
            entry.push(symbol_type);
            entry.push(1);
            entry.extend_from_slice(&0u16.to_le_bytes());
            entry.extend_from_slice(&value.to_le_bytes());
            entry
        };

        let symbols = [
            nlist(1, N_SECT | N_EXT, 0x1000),
            nlist(11, N_SECT, 0x2000),
            nlist(18, N_EXT, 0),
            nlist(1, 0x20 | N_EXT, 0x3000),
            nlist(0x1000, N_SECT | N_EXT, 0x4000),
        ]
        .concat();

        assert_eq!(
            exported_symbols(&symbols, strings),
            [(String::from("_exported"), 0x1000)]
        );
    }

    #[test]
    fn measures_contiguous_segments() {
        // __TEXT, __DATA_CONST and __LINKEDIT of a main executable.
        let segments = [
            (0x100b20000, 0x4000),
            (0x100b24000, 0x4000),
            (0x100b28000, 0x4000),
        ];
        assert_eq!(contiguous_size(&segments, 0x100b20000), 0xc000);

        // An image in the shared cache whose data lives elsewhere.
        let segments = [(0x196b78000, 0x50000), (0x1fc878000, 0x1000), (0, 0)];
        assert_eq!(contiguous_size(&segments, 0x196b78000), 0x50000);

        assert_eq!(contiguous_size(&segments, 0x1000), 0);
    }

    #[test]
    fn clamps_segments_past_the_address_space() {
        // The header segment itself wraps around.
        let segments = [(u64::MAX - 0xfff, 0x2000)];
        assert_eq!(contiguous_size(&segments, u64::MAX - 0xfff), 0xfff);

        // A following segment wraps around.
        let segments = [(u64::MAX - 0x1fff, 0x1000), (u64::MAX - 0xfff, 0x2000)];
        assert_eq!(contiguous_size(&segments, u64::MAX - 0x1fff), 0x1fff);
    }
}
