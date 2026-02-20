//! Portable Executable (PE) module.
//!
//! This module provides high-level abstractions for parsing and analyzing
//! **Portable Executable (PE)** files, which are the standard executable
//! format for Windows operating systems.

mod error;

pub use isr_dl_pdb::CodeView; // re-export the CodeView struct from the isr-dl-pdb crate
pub use object::pe::{ImageDataDirectory, ImageDebugDirectory, ImageDosHeader, ImageFileHeader};
use object::{
    endian::LittleEndian as LE,
    pe::{
        IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
        ImageNtHeaders32 as OImageNtHeaders32, ImageNtHeaders64 as OImageNtHeaders64,
        ImageOptionalHeader32 as OImageOptionalHeader32,
        ImageOptionalHeader64 as OImageOptionalHeader64,
    },
    read::{
        ReadRef as _,
        pe::{
            Export, ExportTable, ImageNtHeaders as OImageNtHeaders, ImageOptionalHeader as _,
            optional_header_magic,
        },
    },
    slice_from_all_bytes,
};
use vmi_core::{Architecture, VmiError, driver::VmiRead, os::VmiOsImage};
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub use self::error::PeError;
use crate::{ArchAdapter, WindowsImage};

/// Portable Executable (PE) NT Headers.
///
/// Represents the **NT Headers** in a **PE file**, which contain crucial
/// metadata for Windows executables and DLLs.
pub struct ImageNtHeaders {
    /// The PE signature.
    signature: u32,

    /// The file header.
    file_header: ImageFileHeader,

    /// The optional header.
    optional_header: ImageOptionalHeader,
}

impl ImageNtHeaders {
    /// Returns the PE signature.
    pub fn signature(&self) -> u32 {
        self.signature
    }

    /// Return the file header.
    pub fn file_header(&self) -> &ImageFileHeader {
        &self.file_header
    }

    /// Return the optional header.
    pub fn optional_header(&self) -> &ImageOptionalHeader {
        &self.optional_header
    }
}

impl From<OImageNtHeaders32> for ImageNtHeaders {
    fn from(value: OImageNtHeaders32) -> Self {
        Self {
            signature: value.signature.get(LE),
            file_header: value.file_header,
            optional_header: ImageOptionalHeader::ImageOptionalHeader32(value.optional_header),
        }
    }
}

impl From<OImageNtHeaders64> for ImageNtHeaders {
    fn from(value: OImageNtHeaders64) -> Self {
        Self {
            signature: value.signature.get(LE),
            file_header: value.file_header,
            optional_header: ImageOptionalHeader::ImageOptionalHeader64(value.optional_header),
        }
    }
}

/// Portable Executable (PE) Optional Header.
///
/// Represents the **Optional Header** in a **PE file**, supporting both
/// **32-bit (PE32)** and **64-bit (PE32+)** formats. It contains essential
/// metadata for loading, memory layout, and execution.
pub enum ImageOptionalHeader {
    /// 32-bit (PE32) optional header.
    ImageOptionalHeader32(OImageOptionalHeader32),

    /// 64-bit (PE32+) optional header.
    ImageOptionalHeader64(OImageOptionalHeader64),
}

macro_rules! impl_image_optional_header_methods {
    (
        $(
            $( #[$meta:meta] )*
            $name:ident: $ty:ty
        ),+ $(,)?
    ) => {
        $(
            $( #[$meta] )*
            pub fn $name(&self) -> $ty {
                match self {
                    Self::ImageOptionalHeader32(hdr32) => hdr32.$name(),
                    Self::ImageOptionalHeader64(hdr64) => hdr64.$name(),
                }
            }
        )*
    }
}

impl ImageOptionalHeader {
    /// Returns the size of the optional header.
    pub fn size(&self) -> usize {
        match self {
            Self::ImageOptionalHeader32(_) => size_of::<OImageOptionalHeader32>(),
            Self::ImageOptionalHeader64(_) => size_of::<OImageOptionalHeader64>(),
        }
    }

    impl_image_optional_header_methods!(
        /// Returns the PE format identifier (PE32 or PE32+).
        magic: u16,

        /// Returns the major linker version.
        major_linker_version: u8,

        /// Returns the minor linker version.
        minor_linker_version: u8,

        /// Returns the size of the executable code section.
        size_of_code: u32,

        /// Returns the size of initialized data (data section).
        size_of_initialized_data: u32,

        /// Returns the size of uninitialized data (bss section).
        size_of_uninitialized_data: u32,

        /// Returns the relative virtual address (RVA) of the entry point.
        ///
        /// When the image is loaded, this is the actual memory address.
        address_of_entry_point: u32,

        /// Returns the RVA of the start of the code section.
        base_of_code: u32,

        /// Returns the RVA of the start of the data section (PE32 only).
        base_of_data: Option<u32>,

        /// Returns the preferred load address in memory.
        ///
        /// The actual base address may change due to ASLR or conflicts.
        image_base: u64,

        /// Returns the section alignment in memory.
        /// This may change when the image is loaded by the OS.
        section_alignment: u32,

        /// Returns the section alignment on disk.
        file_alignment: u32,

        /// Returns the major operating system version required.
        major_operating_system_version: u16,

        /// Returns the minor operating system version required.
        minor_operating_system_version: u16,

        /// Returns the major image version.
        major_image_version: u16,

        /// Returns the minor image version.
        minor_image_version: u16,

        /// Returns the major subsystem version.
        major_subsystem_version: u16,

        /// Returns the minor subsystem version.
        minor_subsystem_version: u16,

        /// Returns the reserved Windows version value (should be zero).
        win32_version_value: u32,

        /// Returns the total size of the image in memory, including headers.
        size_of_image: u32,

        /// Returns the size of all headers (DOS header, PE header, section table).
        size_of_headers: u32,

        /// Returns the checksum of the image.
        check_sum: u32,

        /// Returns the subsystem type (e.g., GUI, console, driver).
        subsystem: u16,

        /// Returns the DLL characteristics (e.g., ASLR, DEP, CFG).
        dll_characteristics: u16,

        /// Returns the reserved stack size.
        size_of_stack_reserve: u64,

        /// Returns the committed stack size.
        size_of_stack_commit: u64,

        /// Returns the reserved heap size.
        size_of_heap_reserve: u64,

        /// Returns the committed heap size.
        size_of_heap_commit: u64,

        /// Returns the reserved loader flags (should be zero).
        loader_flags: u32,

        /// Returns the number of data directories in the optional header.
        number_of_rva_and_sizes: u32,
    );
}

/// Portable Executable (PE) Export Directory.
///
/// Represents the **Export Directory** in a **PE file**, which contains
/// metadata about exported functions, symbols, and addresses. This structure
/// abstracts the export table, storing raw data and directory information.
pub struct PeExportDirectory<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    _marker: std::marker::PhantomData<Driver>,

    /// The export directory entry.
    entry: ImageDataDirectory,

    /// The export directory data.
    data: Vec<u8>,
}

impl<Driver> PeExportDirectory<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new PE export directory parser.
    pub(crate) fn new(
        _image: &WindowsImage<Driver>,
        entry: ImageDataDirectory,
        data: Vec<u8>,
    ) -> Self {
        Self {
            entry,
            data,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the list of exported symbols.
    pub fn exports(&self) -> Result<Vec<Export<'_>>, PeError> {
        let export_table = ExportTable::parse(&self.data, self.entry.virtual_address.get(LE))
            .map_err(|_| PeError::InvalidExportTable)?;

        export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)
    }
}

/// Portable Executable (PE) Debug Directory.
///
/// Represents the **Debug Directory** in a **PE file**, which contains
/// debugging information such as symbols, timestamps, and PDB references.
pub struct PeDebugDirectory<'pe, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    image: &'pe WindowsImage<'pe, Driver>,
    data: Vec<u8>,
}

impl<'pe, Driver> PeDebugDirectory<'pe, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new PE debug directory parser.
    pub(crate) fn new(
        image: &'pe WindowsImage<'pe, Driver>,
        _entry: ImageDataDirectory,
        data: Vec<u8>,
    ) -> Self {
        Self { image, data }
    }

    /// Returns the list of debug directories.
    pub fn debug_directories(&self) -> Option<&[ImageDebugDirectory]> {
        slice_from_all_bytes::<ImageDebugDirectory>(&self.data).ok()
    }

    /// Finds a debug directory by type.
    ///
    /// A debug directory type is represented by `IMAGE_DEBUG_TYPE_*` constants.
    pub fn find_debug_directory(&self, typ: u32) -> Option<&ImageDebugDirectory> {
        self.debug_directories()?.iter().find(|dir| {
            dir.typ.get(LE) == typ
                && dir.address_of_raw_data.get(LE) != 0
                && dir.size_of_data.get(LE) != 0
        })
    }

    /// Returns the CodeView debug information.
    ///
    /// The [`CodeView`] debug information is located in the debug directory
    /// with type [`IMAGE_DEBUG_TYPE_CODEVIEW`].
    pub fn codeview(&self) -> Result<Option<CodeView>, VmiError> {
        const CV_SIGNATURE_RSDS: u32 = 0x53445352; // 'RSDS'

        #[repr(C)]
        #[derive(Debug, FromBytes, Immutable, KnownLayout)]
        struct CvInfoPdb70 {
            signature: u32,
            guid: [u8; 16],
            age: u32,
            // pdb_file_name: [u8],
        }

        let directory = match self.find_debug_directory(IMAGE_DEBUG_TYPE_CODEVIEW) {
            Some(directory) => directory,
            None => return Ok(None),
        };

        if directory.size_of_data.get(LE) < size_of::<CvInfoPdb70>() as u32 {
            tracing::warn!("Invalid CodeView Info size");
            return Ok(None);
        }

        //
        // Read the CodeView debug info.
        //

        let info_address = self.image.base_address() + directory.address_of_raw_data.get(LE) as u64;
        let info_size = directory.size_of_data.get(LE) as usize;

        let mut info_data = vec![0u8; info_size];
        self.image.vmi.read(info_address, &mut info_data)?;

        //
        // Parse the CodeView debug info.
        // Note that the path is located after the `CvInfoPdb70` struct.
        //

        let (info, pdb_file_name) = info_data.split_at(size_of::<CvInfoPdb70>());

        let info = match CvInfoPdb70::ref_from_bytes(info) {
            Ok(info) => info,
            Err(err) => {
                tracing::warn!(?err, "Invalid CodeView Info address");
                return Ok(None);
            }
        };

        if info.signature != CV_SIGNATURE_RSDS {
            tracing::warn!("Invalid CodeView signature");
            return Ok(None);
        }

        //
        // Parse the CodeView path.
        // Note that the path is supposed to be null-terminated,
        // so we need to trim it.
        //

        let path = String::from_utf8_lossy(pdb_file_name)
            .trim_end_matches('\0')
            .to_string();

        let guid0 = u32::from_le_bytes(info.guid[0..4].try_into().unwrap());
        let guid1 = u16::from_le_bytes(info.guid[4..6].try_into().unwrap());
        let guid2 = u16::from_le_bytes(info.guid[6..8].try_into().unwrap());
        let guid3 = &info.guid[8..16];

        #[rustfmt::skip]
        let guid = format!(
            concat!(
                "{:08x}{:04x}{:04x}",
                "{:02x}{:02x}{:02x}{:02x}",
                "{:02x}{:02x}{:02x}{:02x}",
                "{:01x}"
            ),
            guid0, guid1, guid2,
            guid3[0], guid3[1], guid3[2], guid3[3],
            guid3[4], guid3[5], guid3[6], guid3[7],
            info.age & 0xf,
        );

        Ok(Some(CodeView { path, guid }))
    }
}

/// Portable Executable (PE) Representation (32-bit & 64-bit).
///
/// A high-level representation of a **PE file**, supporting both
/// **32-bit (PE32) and 64-bit (PE32+)** formats. It encapsulates
/// the **DOS header, NT headers, and data directories**, providing
/// essential metadata for parsing and analyzing PE binaries.
pub struct Pe {
    /// The DOS header.
    dos_header: ImageDosHeader,

    /// The NT headers.
    nt_headers: ImageNtHeaders,

    /// The data directories.
    data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

impl Pe {
    /// Creates a `Pe` instance by parsing raw PE data.
    pub fn new(data: &[u8]) -> Result<Self, PeError> {
        let magic = optional_header_magic(data).map_err(|_| PeError::InvalidPeMagic)?;

        let mut offset = 0;
        let dos_header = Self::parse_image_dos_header(data, &mut offset)?;
        let nt_headers = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                Self::parse_image_nt_headers::<OImageNtHeaders32>(data, &mut offset)?
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                Self::parse_image_nt_headers::<OImageNtHeaders64>(data, &mut offset)?
            }
            _ => return Err(PeError::InvalidPeMagic),
        };

        // Read the rest of the optional header, and then read
        // the data directories from that.
        let optional_data_size =
            u64::from(nt_headers.file_header().size_of_optional_header.get(LE))
                .checked_sub(nt_headers.optional_header().size() as u64)
                .ok_or(PeError::PeOptionalHeaderSizeTooSmall)?;

        let optional_data = data
            .read_bytes(&mut offset, optional_data_size)
            .map_err(|_| PeError::InvalidPeOptionalHeaderSize)?;

        let data_directories = optional_data
            .read_slice_at(
                0,
                nt_headers.optional_header().number_of_rva_and_sizes() as usize,
            )
            .map_err(|_| PeError::InvalidPeNumberOfRvaAndSizes)?;

        Ok(Self {
            dos_header,
            nt_headers,
            data_directories: std::array::from_fn(|i| {
                data_directories
                    .get(i)
                    .copied()
                    .unwrap_or(ImageDataDirectory {
                        virtual_address: Default::default(),
                        size: Default::default(),
                    })
            }),
        })
    }

    /// Returns the DOS header.
    pub fn dos_header(&self) -> &ImageDosHeader {
        &self.dos_header
    }

    /// Returns the NT headers.
    pub fn nt_headers(&self) -> &ImageNtHeaders {
        &self.nt_headers
    }

    /// Returns the data directories.
    pub fn data_directories(&self) -> &[ImageDataDirectory] {
        &self.data_directories
    }

    /// Parses the DOS header.
    fn parse_image_dos_header(data: &[u8], offset: &mut u64) -> Result<ImageDosHeader, PeError> {
        let dos_header = data
            .read_at::<ImageDosHeader>(0)
            .map_err(|_| PeError::InvalidDosHeaderSizeOrAlignment)?;

        if dos_header.e_magic.get(LE) != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosMagic);
        }

        *offset = dos_header.nt_headers_offset() as u64;

        Ok(*dos_header)
    }

    /// Parses the NT headers.
    fn parse_image_nt_headers<Pe>(data: &[u8], offset: &mut u64) -> Result<ImageNtHeaders, PeError>
    where
        Pe: OImageNtHeaders + Into<ImageNtHeaders>,
    {
        let nt_headers = data
            .read::<Pe>(offset)
            .map_err(|_| PeError::InvalidNtHeadersSizeOrAlignment)?;

        if nt_headers.signature() != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidPeMagic);
        }

        if !nt_headers.is_valid_optional_magic() {
            return Err(PeError::InvalidPeOptionalHeaderMagic);
        }

        Ok((*nt_headers).into())
    }
}
