use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol},
};

use crate::{
    ArchAdapter, MacOs, MacOsError, MacOsImageSymbol, MacOsSegment,
    arch::read_macho,
    macho::{
        MachO, MachSegment, NLIST_64_SIZE, architecture_from_cpu_type, contiguous_size,
        defined_symbols, export_trie_symbols, exported_symbols, named_symbols, string_table_ranges,
    },
};

/// Upper bound on `symtab_command.nsyms`.
const MAX_SYMBOLS: u32 = 1 << 22;

/// Upper bound on `symtab_command.strsize`, in bytes.
const MAX_STRING_TABLE_SIZE: u32 = 64 * 1024 * 1024;

/// Upper bound on the size of the dyld export trie, in bytes.
const MAX_EXPORT_TRIE_SIZE: u32 = 16 * 1024 * 1024;

/// Upper bound on the length of a symbol name read by
/// [`MacOsImage::symbols`], including its NUL terminator, in bytes.
const MAX_SYMBOL_NAME_LENGTH: u32 = 4096;

/// Distance in the string table below which the names read by
/// [`MacOsImage::symbols`] share one read, in bytes.
const STRING_RANGE_GAP: u32 = 0x4000;

/// Upper bound on the bytes of the string table read by
/// [`MacOsImage::symbols`].
const MAX_SYMBOL_STRINGS_SIZE: u64 = 32 * 1024 * 1024;

/// Returns the runtime address of the `size` bytes at `file_offset` of the
/// image, or `None` when they do not lie inside `linkedit`.
fn linkedit_address(linkedit: &MachSegment, slide: u64, file_offset: u64, size: u64) -> Option<Va> {
    let offset = file_offset.checked_sub(linkedit.file_offset)?;
    if offset.checked_add(size)? > linkedit.file_size {
        return None;
    }

    Some(Va(linkedit
        .vm_address
        .wrapping_add(slide)
        .wrapping_add(offset)))
}

/// A 64-bit Mach-O image in memory.
///
/// The image is read through the translation root given at creation, so it
/// can live in the kernel or in the address space of a process.
pub struct MacOsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the Mach-O header.
    va: Va,

    /// Translation root of the address space holding the image.
    root: Pa,
}

impl<Driver> VmiVa for MacOsImage<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Mach-O image with the header at `va` in the address
    /// space rooted at `root`.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, va: Va, root: Pa) -> Self {
        Self { vmi, va, root }
    }

    /// Reads the header and the load commands of the image.
    fn header_bytes(&self) -> Result<Vec<u8>, VmiError> {
        match read_macho(self.vmi.core(), self.va, self.root)? {
            Some(data) => Ok(data),
            None => Err(MacOsError::InvalidMachO("bad magic").into()),
        }
    }

    /// Returns the segments and the slide of the image.
    ///
    /// The slide is the distance between the header in memory and the
    /// `vmaddr` of the `__TEXT` segment, which starts with the header. Images
    /// in the dyld shared cache or in a kernel collection have a non-zero
    /// file offset for `__TEXT`, so the segment is found by name, falling
    /// back to the segment that maps the start of the file.
    fn segments_and_slide(&self, macho: &MachO) -> Result<(Vec<MachSegment>, u64), MacOsError> {
        let segments = macho.segments()?;

        let text = segments
            .iter()
            .find(|segment| segment.name == "__TEXT")
            .or_else(|| {
                segments
                    .iter()
                    .find(|segment| segment.file_offset == 0 && segment.file_size != 0)
            });

        let text = match text {
            Some(text) => text.vm_address,
            None => return Err(MacOsError::InvalidMachO("no __TEXT segment")),
        };

        Ok((segments, self.va.0.wrapping_sub(text)))
    }

    /// Returns the segments of the image at their runtime addresses.
    pub fn segments(&self) -> Result<Vec<MacOsSegment>, VmiError> {
        let data = self.header_bytes()?;
        let macho = MachO::parse(&data)?;
        let (segments, slide) = self.segments_and_slide(&macho)?;

        Ok(segments
            .into_iter()
            .map(|segment| MacOsSegment {
                name: segment.name,
                address: Va(segment.vm_address.wrapping_add(slide)),
                size: segment.vm_size,
            })
            .collect())
    }

    /// Returns the UUID of the image, if it has one.
    pub fn uuid(&self) -> Result<Option<[u8; 16]>, VmiError> {
        let data = self.header_bytes()?;
        Ok(MachO::parse(&data)?.uuid()?)
    }

    /// Returns the size of the image in memory.
    ///
    /// The size covers the segment that holds the header and the segments
    /// that follow it without a gap. Images in the dyld shared cache keep
    /// their other segments elsewhere in the cache, so those segments do not
    /// count.
    pub fn size(&self) -> Result<u64, VmiError> {
        let segments = self
            .segments()?
            .into_iter()
            .map(|segment| (segment.address.0, segment.size))
            .collect::<Vec<_>>();

        Ok(contiguous_size(&segments, self.va.0))
    }

    /// Reads `size` bytes at `va` in the address space of the image.
    ///
    /// Returns `None` when the memory is not readable.
    fn read_optional(&self, va: Va, size: usize) -> Result<Option<Vec<u8>>, VmiError> {
        let mut data = vec![0u8; size];

        match self.vmi.read_in((va, self.root), &mut data) {
            Ok(()) => Ok(Some(data)),
            Err(VmiError::Translation(_) | VmiError::OutOfBounds) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Reads `data` at `va` in the address space of the image.
    ///
    /// Returns `false` when the memory lies outside guest memory. Memory
    /// that is not resident fails with [`VmiError::Translation`].
    fn read_resident(&self, va: Va, data: &mut [u8]) -> Result<bool, VmiError> {
        match self.vmi.read_in((va, self.root), data) {
            Ok(()) => Ok(true),
            Err(VmiError::OutOfBounds) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Returns every symbol defined in a section of the image, local
    /// symbols included.
    ///
    /// Unlike [`exports`], which reads the dyld export trie when there is
    /// one, this reads the `LC_SYMTAB` symbol table, which also lists the
    /// private functions and data of the image. Names are as stored in the
    /// string table and addresses are runtime addresses.
    ///
    /// # Implementation Details
    ///
    /// Keeps the `nlist_64` entries of type `N_SECT` that are not debugging
    /// (stab) entries and have a name. The string table of an image in the
    /// dyld shared cache is shared by all images of the cache and spans
    /// hundreds of megabytes, so only the clusters of it that hold the names
    /// of this image are read, each name being at most 4096 bytes long
    /// including its NUL terminator. A name without a NUL terminator in its
    /// cluster is skipped.
    ///
    /// The result is empty when the image has no symbol table, when the
    /// tables lie outside `__LINKEDIT` or guest memory, or when they exceed
    /// the size limits of 4194304 symbols and 32 MiB of names. Tables that
    /// are not resident fail with [`VmiError::Translation`], so the caller
    /// can page them in and retry. The kernel reclaims its `__LINKEDIT`
    /// after boot, so its tables cannot be read.
    ///
    /// [`exports`]: VmiOsImage::exports
    pub fn symbols(&self) -> Result<Vec<MacOsImageSymbol>, VmiError> {
        let data = self.header_bytes()?;
        let macho = MachO::parse(&data)?;
        let (segments, slide) = self.segments_and_slide(&macho)?;

        let linkedit = match segments.iter().find(|segment| segment.name == "__LINKEDIT") {
            Some(linkedit) => linkedit,
            None => return Ok(Vec::new()),
        };

        let symtab = match macho.symtab()? {
            Some(symtab) => symtab,
            None => return Ok(Vec::new()),
        };

        if symtab.number_of_symbols > MAX_SYMBOLS {
            return Ok(Vec::new());
        }

        let symbols_size = symtab.number_of_symbols as u64 * NLIST_64_SIZE as u64;

        let (symbols_address, strings_address) = match (
            linkedit_address(linkedit, slide, symtab.symbol_offset as u64, symbols_size),
            linkedit_address(
                linkedit,
                slide,
                symtab.string_offset as u64,
                symtab.string_size as u64,
            ),
        ) {
            (Some(symbols), Some(strings)) => (symbols, strings),
            _ => return Ok(Vec::new()),
        };

        let mut nlists = vec![0u8; symbols_size as usize];
        if !self.read_resident(symbols_address, &mut nlists)? {
            return Ok(Vec::new());
        }

        let symbols = defined_symbols(&nlists);
        let ranges = string_table_ranges(
            &symbols,
            symtab.string_size,
            MAX_SYMBOL_NAME_LENGTH,
            STRING_RANGE_GAP,
        );

        let strings_size = ranges
            .iter()
            .map(|range| (range.end - range.start) as u64)
            .sum::<u64>();
        if strings_size > MAX_SYMBOL_STRINGS_SIZE {
            return Ok(Vec::new());
        }

        let mut strings = vec![0u8; strings_size as usize];
        let mut position = 0;
        for range in &ranges {
            let size = (range.end - range.start) as usize;
            let address = strings_address + range.start as u64;

            if !self.read_resident(address, &mut strings[position..position + size])? {
                return Ok(Vec::new());
            }

            position += size;
        }

        Ok(named_symbols(&symbols, &ranges, &strings)
            .into_iter()
            .map(|(name, symbol)| MacOsImageSymbol {
                name,
                address: Va(symbol.value.wrapping_add(slide)),
                external: symbol.external,
            })
            .collect())
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for MacOsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    fn base_address(&self) -> Va {
        self.va
    }

    /// Returns the architecture of the image.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `mach_header_64.cputype`.
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        let data = self.header_bytes()?;
        let macho = MachO::parse(&data)?;
        Ok(architecture_from_cpu_type(macho.header().cpu_type))
    }

    /// Returns the external symbols defined by the image.
    ///
    /// # Implementation Details
    ///
    /// Images loaded by dyld describe their exports with the dyld export trie
    /// (`LC_DYLD_EXPORTS_TRIE` or `LC_DYLD_INFO`), which is read through the
    /// `__LINKEDIT` segment. Re-exported and absolute symbols are not
    /// included. A trie that is not resident fails with
    /// [`VmiError::Translation`], so the caller can page it in and retry.
    /// The string table of an image in the dyld shared cache is shared by
    /// all images of the cache and spans hundreds of megabytes, so its
    /// `LC_SYMTAB` is not used here. [`MacOsImage::symbols`] reads the
    /// `LC_SYMTAB` of such images, local symbols included.
    ///
    /// Images without a trie, such as the kernel and its extensions, use
    /// the `LC_SYMTAB` symbol and string tables. The result is empty when
    /// the image has no symbol table, when the tables lie outside
    /// `__LINKEDIT`, or when they are not readable, as is the case for the
    /// kernel, whose `__LINKEDIT` is reclaimed after boot.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let data = self.header_bytes()?;
        let macho = MachO::parse(&data)?;
        let (segments, slide) = self.segments_and_slide(&macho)?;

        let linkedit = match segments.iter().find(|segment| segment.name == "__LINKEDIT") {
            Some(linkedit) => linkedit,
            None => return Ok(Vec::new()),
        };

        if let Some(trie) = macho.export_trie()? {
            if trie.size > MAX_EXPORT_TRIE_SIZE {
                return Ok(Vec::new());
            }

            let address =
                match linkedit_address(linkedit, slide, trie.offset as u64, trie.size as u64) {
                    Some(address) => address,
                    None => return Ok(Vec::new()),
                };

            let mut trie = vec![0u8; trie.size as usize];
            if !self.read_resident(address, &mut trie)? {
                return Ok(Vec::new());
            }

            return Ok(export_trie_symbols(&trie)
                .into_iter()
                .map(|(name, offset)| VmiOsImageSymbol {
                    name,
                    address: Va(self.va.0.wrapping_add(offset)),
                })
                .collect());
        }

        let symtab = match macho.symtab()? {
            Some(symtab) => symtab,
            None => return Ok(Vec::new()),
        };

        if symtab.number_of_symbols > MAX_SYMBOLS || symtab.string_size > MAX_STRING_TABLE_SIZE {
            return Ok(Vec::new());
        }

        let symbols_size = symtab.number_of_symbols as u64 * NLIST_64_SIZE as u64;
        let strings_size = symtab.string_size as u64;

        let (symbols, strings) = match (
            linkedit_address(linkedit, slide, symtab.symbol_offset as u64, symbols_size),
            linkedit_address(linkedit, slide, symtab.string_offset as u64, strings_size),
        ) {
            (Some(symbols), Some(strings)) => (symbols, strings),
            _ => return Ok(Vec::new()),
        };

        let symbols = match self.read_optional(symbols, symbols_size as usize)? {
            Some(symbols) => symbols,
            None => return Ok(Vec::new()),
        };

        let strings = match self.read_optional(strings, strings_size as usize)? {
            Some(strings) => strings,
            None => return Ok(Vec::new()),
        };

        Ok(exported_symbols(&symbols, &strings)
            .into_iter()
            .map(|(name, value)| VmiOsImageSymbol {
                name,
                address: Va(value.wrapping_add(slide)),
            })
            .collect())
    }
}
