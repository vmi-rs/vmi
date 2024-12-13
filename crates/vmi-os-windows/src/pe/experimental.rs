//! Experimental PE file parser.

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

use super::{codeview::CodeView, error::PeError};
use crate::{arch::ArchAdapter, WindowsOs};

/// A PE export directory.
pub struct PeExportDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pe: &'pe PeParser<'pe, Driver, Pe>,
    data: Vec<u8>,
}

impl<Driver, Pe> PeExportDirectory<'_, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
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
pub struct PeDebugDirectory<'pe, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    pe: &'pe PeParser<'pe, Driver, Pe>,
    data: Vec<u8>,
}

impl<Driver, Pe> PeDebugDirectory<'_, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
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

/// Inner representation of a PE file.
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
pub struct PeParser<'a, Driver, Pe>
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
pub type Pe32<'a, Driver> = PeParser<'a, Driver, ImageNtHeaders32>;

/// Type alias for 64-bit PE files.
pub type Pe64<'a, Driver> = PeParser<'a, Driver, ImageNtHeaders64>;

impl<'a, Driver, Pe> PeParser<'a, Driver, Pe>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
    Pe: ImageNtHeaders,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    /// Creates a new PE parser.
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

    /// Returns the DOS header.
    pub fn dos_header(&self) -> &ImageDosHeader {
        &self.inner.dos_header
    }

    /// Returns the NT headers.
    pub fn nt_headers(&self) -> &Pe {
        &self.inner.nt_headers
    }

    /// Returns the debug directory.
    pub fn debug_directory(&self) -> Result<Option<PeDebugDirectory<Driver, Pe>>, VmiError> {
        let data = match self.read_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeDebugDirectory { pe: self, data }))
    }

    /// Returns the export directory.
    pub fn export_directory(&self) -> Result<Option<PeExportDirectory<Driver, Pe>>, VmiError> {
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
        self.vmi.read(
            self.registers
                .address_context(self.image_base + virtual_address as u64),
            &mut data,
        )?;

        Ok(Some(data))
    }
}
