//! Portable Executable (PE) parsing.
//!
//! Parses PE/COFF binaries from VMI memory or file buffers, exposing the
//! DOS and NT headers, the data directory array, and the standard export,
//! debug, and exception directory layouts.

mod error;
mod file;
mod headers;

pub use isr_dl_windows::CodeView; // Intentional re-export.
use vmi_core::VmiError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub use self::{
    error::PeError,
    file::PeFile,
    headers::{
        Export, ExportTable, ExportTarget, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, IMAGE_DIRECTORY_ENTRY_BASERELOC,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
        IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_RESOURCE,
        IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_SIGNATURE,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory, ImageDebugDirectory, ImageDosHeader,
        ImageFileHeader, ImageNtHeaders, ImageOptionalHeader, ImageOptionalHeader32,
        ImageOptionalHeader64, ImageRuntimeFunctionEntry, ImageSectionHeader,
    },
};

/// Trait for reading PE image data.
///
/// Abstracts the source of PE data - either VMI memory ([`WindowsImage`])
/// or a local file buffer ([`PeFile`]). Directory accessors are provided
/// as default methods.
///
/// [`WindowsImage`]: crate::WindowsImage
pub trait PeImage
where
    Self: Sized,
{
    /// Reads data at the given RVA within the image.
    fn read_at_rva(&self, rva: u32, buf: &mut [u8]) -> Result<(), VmiError>;

    /// Reads a struct of type `T` at the given RVA within the image.
    fn read_struct_at_rva<T>(&self, rva: u32) -> Result<T, VmiError>
    where
        T: FromBytes + IntoBytes,
    {
        let mut result = T::new_zeroed();
        self.read_at_rva(rva, result.as_mut_bytes())?;
        Ok(result)
    }

    /// Returns the DOS header.
    fn dos_header(&self) -> Result<&ImageDosHeader, VmiError>;

    /// Returns the NT headers.
    fn nt_headers(&self) -> Result<&ImageNtHeaders, VmiError>;

    /// Returns the export directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]`.
    fn export_directory(&self) -> Result<Option<PeExportDirectory<'_, Self>>, VmiError>;

    /// Returns the exception directory (.pdata section).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]`.
    fn exception_directory(&self) -> Result<Option<PeExceptionDirectory<'_, Self>>, VmiError>;

    /// Returns the debug directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]`.
    fn debug_directory(&self) -> Result<Option<PeDebugDirectory<'_, Self>>, VmiError>;
}

/// PE export directory accessor.
///
/// # Implementation Details
///
/// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]`.
pub struct PeExportDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Directory entry that located the export table.
    entry: ImageDataDirectory,

    /// Raw bytes read at the directory's RVA.
    data: Vec<u8>,
}

impl<'a, Image: PeImage> PeExportDirectory<'a, Image> {
    /// Creates a new PE export directory parser.
    pub(crate) fn new(image: &'a Image, entry: ImageDataDirectory, data: Vec<u8>) -> Self {
        Self { image, entry, data }
    }

    /// Returns the list of exported symbols.
    pub fn exports(&self) -> Result<Vec<Export<'_>>, PeError> {
        let export_table = ExportTable::parse(&self.data, self.entry.virtual_address)
            .map_err(|_| PeError::InvalidExportTable)?;

        export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)
    }
}

/// PE exception directory accessor (.pdata section).
///
/// Holds the `RUNTIME_FUNCTION` table used for x64 stack unwinding.
///
/// # Implementation Details
///
/// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]`.
pub struct PeExceptionDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Raw bytes read at the directory's RVA.
    data: Vec<u8>,
}

impl<'a, Image: PeImage> PeExceptionDirectory<'a, Image> {
    /// Creates a new PE exception directory parser.
    pub(crate) fn new(image: &'a Image, data: Vec<u8>) -> Self {
        Self { image, data }
    }

    /// Returns the `RUNTIME_FUNCTION` entries as a slice.
    pub fn runtime_functions(&self) -> Option<&[ImageRuntimeFunctionEntry]> {
        <[ImageRuntimeFunctionEntry]>::ref_from_bytes(&self.data).ok()
    }

    /// Finds the `RUNTIME_FUNCTION` entry containing the given RVA.
    ///
    /// Uses binary search over the sorted entries.
    pub fn find(&self, rva: u32) -> Option<&ImageRuntimeFunctionEntry> {
        let entries = self.runtime_functions()?;
        let index = entries
            .binary_search_by(|entry| {
                use std::cmp::Ordering;

                let begin = entry.begin_address;
                let end = entry.end_address;
                if rva < begin {
                    Ordering::Greater
                }
                else if rva >= end {
                    Ordering::Less
                }
                else {
                    Ordering::Equal
                }
            })
            .ok()?;

        Some(&entries[index])
    }
}

/// PE debug directory accessor.
///
/// # Implementation Details
///
/// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]`.
pub struct PeDebugDirectory<'a, Image: PeImage> {
    /// Owning image.
    image: &'a Image,

    /// Raw bytes read at the directory's RVA.
    data: Vec<u8>,
}

impl<'a, Image: PeImage> PeDebugDirectory<'a, Image> {
    /// Creates a new PE debug directory parser.
    pub(crate) fn new(image: &'a Image, data: Vec<u8>) -> Self {
        Self { image, data }
    }

    /// Returns the list of debug directories.
    pub fn debug_directories(&self) -> Option<&[ImageDebugDirectory]> {
        <[ImageDebugDirectory]>::ref_from_bytes(&self.data).ok()
    }

    /// Finds a debug directory by type.
    ///
    /// A debug directory type is represented by `IMAGE_DEBUG_TYPE_*` constants.
    pub fn find_debug_directory(&self, typ: u32) -> Option<&ImageDebugDirectory> {
        self.debug_directories()?
            .iter()
            .find(|dir| dir.typ == typ && dir.address_of_raw_data != 0 && dir.size_of_data != 0)
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

        if directory.size_of_data < size_of::<CvInfoPdb70>() as u32 {
            tracing::warn!("Invalid CodeView Info size");
            return Ok(None);
        }

        //
        // Read the CodeView debug info.
        //

        let rva = directory.address_of_raw_data;
        let info_size = directory.size_of_data as usize;

        let mut info_data = vec![0u8; info_size];
        self.image.read_at_rva(rva, &mut info_data)?;

        //
        // Parse the CodeView debug info.
        // Note that the path is located after the `CvInfoPdb70` struct.
        //

        let (info, pdb_file_name) = info_data.split_at(size_of::<CvInfoPdb70>());

        let info = match CvInfoPdb70::ref_from_bytes(info) {
            Ok(info) => info,
            Err(err) => {
                tracing::warn!(%err, "Invalid CodeView Info address");
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

        let name = String::from_utf8_lossy(pdb_file_name)
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
            ),
            guid0, guid1, guid2,
            guid3[0], guid3[1], guid3[2], guid3[3],
            guid3[4], guid3[5], guid3[6], guid3[7],
        );

        Ok(Some(CodeView {
            name,
            guid,
            age: info.age & 0xf,
        }))
    }
}

/// Parsed PE/COFF header.
///
/// Same shape for PE32 and PE32+, with the bitness recoverable from
/// [`ImageOptionalHeader::magic`].
pub struct PeHeader {
    /// The DOS header.
    dos_header: ImageDosHeader,

    /// The NT headers.
    nt_headers: ImageNtHeaders,

    /// The data directories.
    data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],

    /// The file offset where the section table begins.
    section_table_offset: u64,
}

impl PeHeader {
    /// Parses the DOS header, NT headers, and data directory array from
    /// raw PE bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PeError> {
        let mut offset = 0;
        let dos_header = ImageDosHeader::parse(data, &mut offset)?;
        let nt_headers = ImageNtHeaders::parse(data, &mut offset)?;

        // Read the rest of the optional header, and then read
        // the data directories from that.
        let optional_data_size = u64::from(nt_headers.file_header.size_of_optional_header)
            .checked_sub(nt_headers.optional_header.size() as u64)
            .ok_or(PeError::OptionalHeaderTooSmall)?;

        let optional_data = data
            .get(offset as usize..)
            .ok_or(PeError::InvalidOptionalHeaderSize)?
            .get(..optional_data_size as usize)
            .ok_or(PeError::InvalidOptionalHeaderSize)?;

        offset += optional_data_size;

        let (data_directories, _) = <[ImageDataDirectory]>::ref_from_prefix_with_elems(
            optional_data,
            nt_headers.optional_header.number_of_rva_and_sizes() as usize,
        )
        .map_err(|_| PeError::InvalidDataDirectoryCount)?;

        Ok(Self {
            dos_header,
            nt_headers,
            data_directories: std::array::from_fn(|i| {
                data_directories
                    .get(i)
                    .copied()
                    .unwrap_or(ImageDataDirectory {
                        virtual_address: 0,
                        size: 0,
                    })
            }),
            section_table_offset: offset,
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

    /// Returns the offset of the section table within the PE data.
    pub fn section_table_offset(&self) -> u64 {
        self.section_table_offset
    }
}
