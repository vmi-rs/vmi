//! Dummy doc

pub(super) mod codeview;
mod error;
pub mod experimental;

use object::{
    endian::LittleEndian as LE,
    pe::{
        ImageDataDirectory, ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64,
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
    },
    read::{
        pe::{Export, ExportTable, ImageNtHeaders, ImageOptionalHeader},
        ReadRef as _,
    },
};

pub use self::{codeview::CodeView, error::PeError};

/// A lightweight Portable Executable (PE) file parser.
///
/// The generic parameter `Pe` determines whether this handles 32-bit or 64-bit
/// PE files through the [`ImageNtHeaders`] trait.
pub struct PeLite<'a, Pe>
where
    Pe: ImageNtHeaders,
{
    /// The DOS header from the PE file.
    pub dos_header: &'a ImageDosHeader,

    /// The NT headers containing file header and optional header.
    pub nt_headers: &'a Pe,

    /// Array of data directory entries describing locations of various tables.
    pub data_directories: &'a [ImageDataDirectory],
}

/// Type alias for 32-bit PE files.
pub type PeLite32<'a> = PeLite<'a, ImageNtHeaders32>;

/// Type alias for 64-bit PE files.
pub type PeLite64<'a> = PeLite<'a, ImageNtHeaders64>;

impl<'a, Pe> PeLite<'a, Pe>
where
    Pe: ImageNtHeaders,
{
    /// Parses a PE file from raw bytes.
    ///
    /// This method performs all necessary validation of the PE file structure:
    /// - Validates DOS header magic and alignment
    /// - Validates NT headers signature and magic
    /// - Validates optional header size and content
    /// - Reads data directories
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        // Parse the DOS header
        let dos_header = data
            .read_at::<ImageDosHeader>(0)
            .map_err(|_| PeError::InvalidDosHeaderSizeOrAlignment)?;

        if dos_header.e_magic.get(LE) != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosMagic);
        }

        // Parse the NT headers
        let mut offset = dos_header.nt_headers_offset() as u64;

        let nt_headers = data
            .read::<Pe>(&mut offset)
            .map_err(|_| PeError::InvalidNtHeadersSizeOrAlignment)?;

        if nt_headers.signature() != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidPeMagic);
        }
        if !nt_headers.is_valid_optional_magic() {
            return Err(PeError::InvalidPeOptionalHeaderMagic);
        }

        // Read the rest of the optional header, and then read the data directories from
        // that.
        let optional_data_size =
            u64::from(nt_headers.file_header().size_of_optional_header.get(LE))
                .checked_sub(size_of::<Pe::ImageOptionalHeader>() as u64)
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
            data_directories,
        })
    }

    /// Extracts the export table from the PE file.
    ///
    /// Reads and parses the export directory from the PE file, returning a vector
    /// of all exported symbols. The export table contains information about functions
    /// and data that the PE file exposes for use by other modules.
    pub fn exports(&self, data: &'a [u8]) -> Result<Vec<Export>, PeError> {
        let entry = self.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        let export_table = ExportTable::parse(data, entry.virtual_address.get(LE))
            .map_err(|_| PeError::InvalidExportTable)?;

        export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)
    }
}
