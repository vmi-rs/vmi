//! Experimental PE file parser.

pub use object::pe::{ImageDataDirectory, ImageDebugDirectory, ImageDosHeader, ImageFileHeader};
use object::{
    endian::LittleEndian as LE,
    pe::{
        ImageNtHeaders32 as OImageNtHeaders32, ImageNtHeaders64 as OImageNtHeaders64,
        ImageOptionalHeader32 as OImageOptionalHeader32,
        ImageOptionalHeader64 as OImageOptionalHeader64, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    },
    read::{
        pe::{
            optional_header_magic, Export, ExportTable, ImageNtHeaders as OImageNtHeaders,
            ImageOptionalHeader as _,
        },
        ReadRef as _,
    },
    slice_from_all_bytes,
};
use vmi_core::{Architecture, Va, VmiDriver, VmiError, VmiState};
use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::{codeview::CodeView, error::PeError};
use crate::{arch::ArchAdapter, WindowsOs, WindowsOsImage};

pub struct ImageNtHeaders {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader,
}

impl ImageNtHeaders {
    /// Return the signature
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
    fn from(nt_headers: OImageNtHeaders32) -> Self {
        Self {
            signature: nt_headers.signature.get(LE),
            file_header: nt_headers.file_header,
            optional_header: ImageOptionalHeader::ImageOptionalHeader32(nt_headers.optional_header),
        }
    }
}

impl From<OImageNtHeaders64> for ImageNtHeaders {
    fn from(nt_headers: OImageNtHeaders64) -> Self {
        Self {
            signature: nt_headers.signature.get(LE),
            file_header: nt_headers.file_header,
            optional_header: ImageOptionalHeader::ImageOptionalHeader64(nt_headers.optional_header),
        }
    }
}

pub enum ImageOptionalHeader {
    ImageOptionalHeader32(OImageOptionalHeader32),
    ImageOptionalHeader64(OImageOptionalHeader64),
}

macro_rules! impl_image_optional_header_methods {
    ($($name:ident: $ty:ty,)*) => {
        $(
            pub fn $name(&self) -> $ty {
                match self {
                    Self::ImageOptionalHeader32(optional_header) => optional_header.$name(),
                    Self::ImageOptionalHeader64(optional_header) => optional_header.$name(),
                }
            }
        )*
    };
}

impl ImageOptionalHeader {
    pub fn size(&self) -> usize {
        match self {
            Self::ImageOptionalHeader32(_) => size_of::<OImageOptionalHeader32>(),
            Self::ImageOptionalHeader64(_) => size_of::<OImageOptionalHeader64>(),
        }
    }

    impl_image_optional_header_methods!(
        magic: u16,
        major_linker_version: u8,
        minor_linker_version: u8,
        size_of_code: u32,
        size_of_initialized_data: u32,
        size_of_uninitialized_data: u32,
        address_of_entry_point: u32,
        base_of_code: u32,
        base_of_data: Option<u32>,
        image_base: u64,
        section_alignment: u32,
        file_alignment: u32,
        major_operating_system_version: u16,
        minor_operating_system_version: u16,
        major_image_version: u16,
        minor_image_version: u16,
        major_subsystem_version: u16,
        minor_subsystem_version: u16,
        win32_version_value: u32,
        size_of_image: u32,
        size_of_headers: u32,
        check_sum: u32,
        subsystem: u16,
        dll_characteristics: u16,
        size_of_stack_reserve: u64,
        size_of_stack_commit: u64,
        size_of_heap_reserve: u64,
        size_of_heap_commit: u64,
        loader_flags: u32,
        number_of_rva_and_sizes: u32,
    );
}

/// A PE export directory.
pub struct PeExportDirectory<'pe, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    pe: &'pe PeParser<'pe, Driver>,
    data: Vec<u8>,
}

impl<Driver> PeExportDirectory<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Returns the list of exported symbols.
    pub fn exports(&self) -> Result<Vec<Export>, PeError> {
        let entry = self.pe.inner.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        let export_table = ExportTable::parse(&self.data, entry.virtual_address.get(LE))
            .map_err(|_| PeError::InvalidExportTable)?;

        export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)
    }
}

/// A PE debug directory.
pub struct PeDebugDirectory<'pe, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    image: &'pe WindowsOsImage<'pe, Driver>,
    data: Vec<u8>,
}

impl<'pe, Driver> PeDebugDirectory<'pe, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    pub(crate) fn new(image: &'pe WindowsOsImage<'pe, Driver>, data: Vec<u8>) -> Self {
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
    /// The CodeView debug information is located in the debug directory
    /// with type `IMAGE_DEBUG_TYPE_CODEVIEW`.
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

        let info_address = self.pe.image_base + directory.address_of_raw_data.get(LE) as u64;
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

/// Inner representation of a PE file.
pub struct Pe {
    dos_header: ImageDosHeader,
    nt_headers: ImageNtHeaders,
    data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

impl Pe {
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

    pub fn dos_header(&self) -> &ImageDosHeader {
        &self.dos_header
    }

    pub fn nt_headers(&self) -> &ImageNtHeaders {
        &self.nt_headers
    }

    pub fn data_directories(&self) -> &[ImageDataDirectory] {
        &self.data_directories
    }

    fn parse_image_dos_header(data: &[u8], offset: &mut u64) -> Result<ImageDosHeader, PeError> {
        // Parse the DOS header
        let dos_header = data
            .read_at::<ImageDosHeader>(0)
            .map_err(|_| PeError::InvalidDosHeaderSizeOrAlignment)?;

        if dos_header.e_magic.get(LE) != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosMagic);
        }

        *offset = dos_header.nt_headers_offset() as u64;

        Ok(*dos_header)
    }

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

/// A lightweight Portable Executable (PE) file parser.
///
/// The generic parameter `Pe` determines whether this handles 32-bit or 64-bit
/// PE files through the [`ImageNtHeaders`] trait.
pub struct PeParser<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
    image_base: Va,
    inner: Pe,
}

impl<'a, Driver> PeParser<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    /// Creates a new PE parser.
    pub fn new(
        vmi: &'a VmiState<'a, Driver, WindowsOs<Driver>>,
        image_base: Va,
    ) -> Result<Self, VmiError> {
        let mut data = vec![0; Driver::Architecture::PAGE_SIZE as usize];
        vmi.read(image_base, &mut data)?;

        Ok(Self {
            vmi,
            image_base,
            inner: Pe::new(&data).map_err(|err| VmiError::Os(err.into()))?,
        })
    }

    /// Returns the DOS header.
    pub fn dos_header(&self) -> &ImageDosHeader {
        &self.inner.dos_header
    }

    /// Returns the NT headers.
    pub fn nt_headers(&self) -> &ImageNtHeaders {
        &self.inner.nt_headers
    }

    /// Returns the debug directory.
    pub fn debug_directory(&self) -> Result<Option<PeDebugDirectory<Driver>>, VmiError> {
        let data = match self.read_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeDebugDirectory { pe: self, data }))
    }

    /// Returns the export directory.
    pub fn export_directory(&self) -> Result<Option<PeExportDirectory<Driver>>, VmiError> {
        let data = match self.read_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeExportDirectory { pe: self, data }))
    }

    /// Reads a data directory by index.
    fn read_data_directory(&self, index: usize) -> Result<Option<Vec<u8>>, VmiError> {
        let (virtual_address, size) = match self.inner.data_directories.get(index) {
            Some(entry) => (entry.virtual_address.get(LE), entry.size.get(LE)),
            None => return Ok(None),
        };

        if virtual_address == 0 || size == 0 || size > Self::MAX_DATA_DIRECTORY_SIZE {
            return Ok(None);
        }

        let mut data = vec![0; size as usize];
        self.vmi
            .read(self.image_base + virtual_address as u64, &mut data)?;

        Ok(Some(data))
    }
}
