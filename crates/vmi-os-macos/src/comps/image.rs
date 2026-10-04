use vmi_core::{
    Pa, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol},
};

use crate::{
    ArchAdapter, MacOs, MacOsError, MacOsSegment,
    arch::read_macho,
    macho::{
        MachO, MachSegment, NLIST_64_SIZE, architecture_from_cpu_type, contiguous_size,
        exported_symbols,
    },
};

/// Upper bound on `symtab_command.nsyms`.
const MAX_SYMBOLS: u32 = 1 << 22;

/// Upper bound on `symtab_command.strsize`, in bytes.
const MAX_STRING_TABLE_SIZE: u32 = 64 * 1024 * 1024;

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
    /// Reads the `LC_SYMTAB` symbol and string tables through the
    /// `__LINKEDIT` segment. The result is empty when the image has no
    /// symbol table, when the tables lie outside `__LINKEDIT`, or when they
    /// are not readable, as is the case for the kernel, whose `__LINKEDIT`
    /// is reclaimed after boot. Symbols exported only through the dyld
    /// export trie are not included.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let data = self.header_bytes()?;
        let macho = MachO::parse(&data)?;

        let symtab = match macho.symtab()? {
            Some(symtab) => symtab,
            None => return Ok(Vec::new()),
        };

        if symtab.number_of_symbols > MAX_SYMBOLS || symtab.string_size > MAX_STRING_TABLE_SIZE {
            return Ok(Vec::new());
        }

        let (segments, slide) = self.segments_and_slide(&macho)?;

        let linkedit = match segments.iter().find(|segment| segment.name == "__LINKEDIT") {
            Some(linkedit) => linkedit,
            None => return Ok(Vec::new()),
        };

        // Translates a file range to a runtime address inside `__LINKEDIT`.
        let linkedit_address = |file_offset: u64, size: u64| {
            let offset = file_offset.checked_sub(linkedit.file_offset)?;
            if offset.checked_add(size)? > linkedit.file_size {
                return None;
            }

            Some(Va(linkedit
                .vm_address
                .wrapping_add(slide)
                .wrapping_add(offset)))
        };

        let symbols_size = symtab.number_of_symbols as u64 * NLIST_64_SIZE as u64;
        let strings_size = symtab.string_size as u64;

        let (symbols, strings) = match (
            linkedit_address(symtab.symbol_offset as u64, symbols_size),
            linkedit_address(symtab.string_offset as u64, strings_size),
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
