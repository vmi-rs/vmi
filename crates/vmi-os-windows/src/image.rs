use object::{
    endian::LittleEndian as LE,
    pe::{ImageDataDirectory, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXPORT},
    read::pe::ExportTarget,
};
use once_cell::unsync::OnceCell;
use vmi_core::{
    os::{OsArchitecture, OsImageExportedSymbol, VmiOsImage},
    Architecture, Va, VmiDriver, VmiError, VmiState,
};

use crate::{
    arch::ArchAdapter,
    pe2::{
        ImageDosHeader, ImageNtHeaders, ImageOptionalHeader, Pe, PeDebugDirectory,
        PeExportDirectory,
    },
    WindowsOs,
};

/// A Windows OS image.
pub struct WindowsOsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    pub(crate) vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The base address of the image.
    va: Va,

    /// Cached PE parser.
    pe: OnceCell<Pe>,
}

impl<'a, Driver> WindowsOsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    /// Creates a new Windows OS image.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            pe: OnceCell::new(),
        }
    }

    /// Returns the DOS header.
    pub fn dos_header(&self) -> Result<&ImageDosHeader, VmiError> {
        Ok(&self.pe()?.dos_header())
    }

    /// Returns the NT headers.
    pub fn nt_headers(&self) -> Result<&ImageNtHeaders, VmiError> {
        Ok(&self.pe()?.nt_headers())
    }

    /// Returns the debug directory.
    pub fn debug_directory(&self) -> Result<Option<PeDebugDirectory<Driver>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;

        Ok(Some(PeDebugDirectory::new(self, entry, data)))
    }

    /// Returns the export directory.
    pub fn export_directory(&self) -> Result<Option<PeExportDirectory<Driver>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;

        Ok(Some(PeExportDirectory::new(self, entry, data)))
    }

    /// Reads a data directory by index.
    fn find_data_directory(&self, index: usize) -> Result<Option<ImageDataDirectory>, VmiError> {
        let entry = match self.pe()?.data_directories().get(index).copied() {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if entry.virtual_address.get(LE) == 0
            || entry.size.get(LE) == 0
            || entry.size.get(LE) > Self::MAX_DATA_DIRECTORY_SIZE
        {
            return Ok(None);
        }

        Ok(Some(entry))
    }

    /// Reads a data directory by index.
    fn read_data_directory(&self, entry: &ImageDataDirectory) -> Result<Vec<u8>, VmiError> {
        let mut data = vec![0; entry.size.get(LE) as usize];
        self.vmi
            .read(self.va + entry.virtual_address.get(LE) as u64, &mut data)?;

        Ok(data)
    }

    fn pe(&self) -> Result<&Pe, VmiError> {
        self.pe.get_or_try_init(|| {
            let mut data = vec![0; Driver::Architecture::PAGE_SIZE as usize];
            self.vmi.read(self.va, &mut data)?;
            Pe::new(&data).map_err(|err| VmiError::Os(err.into()))
        })
    }
}

impl<'a, Driver> VmiOsImage for WindowsOsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Returns the base address of the image.
    fn base_address(&self) -> Va {
        self.va
    }

    fn architecture(&self) -> Result<OsArchitecture, VmiError> {
        match self.pe()?.nt_headers().optional_header() {
            ImageOptionalHeader::ImageOptionalHeader32(_) => Ok(OsArchitecture::X86),
            ImageOptionalHeader::ImageOptionalHeader64(_) => Ok(OsArchitecture::Amd64),
        }
    }

    fn exports(&self) -> Result<Vec<OsImageExportedSymbol>, VmiError> {
        let directory = match self.export_directory()? {
            Some(directory) => directory,
            None => return Ok(Vec::new()),
        };

        Ok(directory
            .exports()?
            .into_iter()
            .filter_map(|export| match export.target {
                ExportTarget::Address(address) => Some(OsImageExportedSymbol {
                    name: String::from_utf8_lossy(export.name?).to_string(),
                    address: self.va + address as u64,
                }),
                _ => None,
            })
            .collect())
    }
}
