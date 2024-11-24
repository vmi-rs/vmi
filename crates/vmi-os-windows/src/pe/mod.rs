pub(super) mod codeview;
mod error;

use object::{
    endian::LittleEndian as LE,
    pe::{
        ImageDataDirectory, ImageDebugDirectory, ImageDosHeader, ImageNtHeaders32,
        ImageNtHeaders64, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG,
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    },
    read::{
        pe::{Export, ExportTable, ImageNtHeaders, ImageOptionalHeader},
        ReadRef as _,
    },
    slice_from_all_bytes,
};
use vmi_core::{Architecture, Registers, Va, VmiDriver, VmiError, VmiSession};
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub use self::{
    codeview::{codeview_from_pe, CodeView},
    error::PeError,
};
use crate::{arch::ArchAdapter, WindowsOs};

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

////////////////////////////////////////////////////////////////////////////////

pub struct PeExportDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pe: &'pe PeNEW<'pe, Driver, Pe>,
    data: Vec<u8>,
}

impl<'pe, Driver, Pe> PeExportDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pub fn exports(&self) -> Result<Vec<Export>, PeError> {
        let entry = self.pe.inner.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        let export_table = ExportTable::parse(&self.data, entry.virtual_address.get(LE))
            .map_err(|_| PeError::InvalidExportTable)?;

        export_table
            .exports()
            .map_err(|_| PeError::InvalidExportTable)
    }
}

pub struct PeDebugDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pe: &'pe PeNEW<'pe, Driver, Pe>,
    data: Vec<u8>,
}

impl<'pe, Driver, Pe> PeDebugDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pub fn debug_directories(&self) -> Option<&[ImageDebugDirectory]> {
        slice_from_all_bytes::<ImageDebugDirectory>(&self.data).ok()
    }

    pub fn find_debug_directory(&self, typ: u32) -> Option<&ImageDebugDirectory> {
        self.debug_directories()?.iter().find(|dir| {
            dir.typ.get(LE) == typ
                && dir.address_of_raw_data.get(LE) != 0
                && dir.size_of_data.get(LE) != 0
        })
    }

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
        self.pe.vmi.read(
            self.pe.registers.address_context(info_address),
            &mut info_data,
        )?;

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

struct PeInner<Pe>
where
    Pe: ImageNtHeaders,
{
    dos_header: ImageDosHeader,
    nt_headers: Pe,
    data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

impl<Pe> PeInner<Pe>
where
    Pe: ImageNtHeaders,
{
    fn new(data: &[u8]) -> Result<Self, PeError> {
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

        // Read the rest of the optional header, and then read
        // the data directories from that.
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
            dos_header: *dos_header,
            nt_headers: *nt_headers,
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
}

/// A lightweight Portable Executable (PE) file parser.
///
/// The generic parameter `Pe` determines whether this handles 32-bit or 64-bit
/// PE files through the [`ImageNtHeaders`] trait.
pub struct PeNEW<'a, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
    registers: &'a <Driver::Architecture as Architecture>::Registers,
    image_base: Va,
    inner: PeInner<Pe>,
}

/// Type alias for 32-bit PE files.
pub type PeNEW32<'a, Driver> = PeNEW<'a, Driver, ImageNtHeaders32>;

/// Type alias for 64-bit PE files.
pub type PeNEW64<'a, Driver> = PeNEW<'a, Driver, ImageNtHeaders64>;

impl<'a, Driver, Pe> PeNEW<'a, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    ///
    pub fn new(
        vmi: VmiSession<'a, Driver, WindowsOs<Driver>>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<Self, VmiError> {
        let mut data = vec![0; Driver::Architecture::PAGE_SIZE as usize];
        vmi.read(registers.address_context(image_base), &mut data)?;

        Ok(Self {
            vmi,
            registers,
            image_base,
            inner: PeInner::new(&data).map_err(|err| VmiError::Os(err.into()))?,
        })
    }

    ///
    pub fn dos_header(&self) -> &ImageDosHeader {
        &self.inner.dos_header
    }

    ///
    pub fn nt_headers(&self) -> &Pe {
        &self.inner.nt_headers
    }

    ///
    pub fn debug_directory(&self) -> Result<Option<PeDebugDirectory<Driver, Pe>>, VmiError> {
        let data = match self.read_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeDebugDirectory { pe: self, data }))
    }

    ///
    pub fn export_directory(&self) -> Result<Option<PeExportDirectory<Driver, Pe>>, VmiError> {
        let data = match self.read_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeExportDirectory { pe: self, data }))
    }

    fn read_data_directory(&self, index: usize) -> Result<Option<Vec<u8>>, VmiError> {
        let (virtual_address, size) = match self.inner.data_directories.get(index) {
            Some(entry) => (entry.virtual_address.get(LE), entry.size.get(LE)),
            None => return Ok(None),
        };

        if virtual_address == 0 || size == 0 || size > Self::MAX_DATA_DIRECTORY_SIZE {
            return Ok(None);
        }

        let mut data = vec![0; size as usize];
        self.vmi.read(
            self.registers
                .address_context(self.image_base + virtual_address as u64),
            &mut data,
        )?;

        Ok(Some(data))
    }
}
