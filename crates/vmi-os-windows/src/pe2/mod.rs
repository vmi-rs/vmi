mod error;

pub use object::pe::{ImageDataDirectory, ImageDebugDirectory, ImageDosHeader, ImageFileHeader};
use object::{
    endian::LittleEndian as LE,
    pe::{
        ImageNtHeaders32 as OImageNtHeaders32, ImageNtHeaders64 as OImageNtHeaders64,
        ImageOptionalHeader32 as OImageOptionalHeader32,
        ImageOptionalHeader64 as OImageOptionalHeader64, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
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
use vmi_core::{Architecture, VmiDriver, VmiError};
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::{
    arch::ArchAdapter,
    pe::{codeview::CodeView, PeError},
    WindowsOsImage,
};

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

/// Information for parsing a PE export directory.
pub struct PeExportDirectory<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    _marker: std::marker::PhantomData<Driver>,
    entry: ImageDataDirectory,
    data: Vec<u8>,
}

impl<Driver> PeExportDirectory<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Creates a new PE export directory parser.
    pub(super) fn new(
        _image: &WindowsOsImage<Driver>,
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
    pub fn exports(&self) -> Result<Vec<Export>, VmiError> {
        let export_table = ExportTable::parse(&self.data, self.entry.virtual_address.get(LE))
            .map_err(|_| PeError::InvalidExportTable)?;

        Ok(export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)?)
    }
}

/// Information for parsing a PE debug directory.
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
    /// Creates a new PE debug directory parser.
    pub(super) fn new(
        image: &'pe WindowsOsImage<'pe, Driver>,
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

/// A PE file parser.
pub struct Pe {
    dos_header: ImageDosHeader,
    nt_headers: ImageNtHeaders,
    data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

impl Pe {
    /// Creates a new PE file parser.
    pub fn new(data: &[u8]) -> Result<Self, VmiError> {
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
            _ => return Err(VmiError::Os(PeError::InvalidPeMagic.into())),
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
