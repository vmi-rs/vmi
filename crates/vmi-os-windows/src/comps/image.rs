use object::{
    endian::LittleEndian as LE,
    pe::{IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXPORT, ImageDataDirectory},
    read::pe::ExportTarget,
};
use once_cell::unsync::OnceCell;
use vmi_core::{
    Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa,
    os::{VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol},
};

use crate::{
    ArchAdapter, WindowsError, WindowsOs,
    pe::{
        ImageDosHeader, ImageNtHeaders, ImageOptionalHeader, Pe, PeDebugDirectory,
        PeExportDirectory,
    },
};

/// A Windows executable image (PE).
///
/// A Windows image is an executable or DLL mapped into memory.
pub struct WindowsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state (without the OS context).
    ///
    /// The OS context is omitted so that the image can be used
    /// in [`ArchAdapter::find_kernel`], where the OS context is
    /// not available.
    pub(crate) vmi: VmiState<'a, Driver>,

    /// The base address of the image.
    va: Va,

    /// Cached PE parser.
    pe: OnceCell<Pe>,
}

impl<Driver> VmiVa for WindowsImage<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    /// Creates a new Windows image.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self::new_without_os(vmi.without_os(), va)
    }

    /// Creates a new Windows image without the OS context.
    pub(crate) fn new_without_os(vmi: VmiState<'a, Driver>, va: Va) -> Self {
        Self {
            vmi,
            va,
            pe: OnceCell::new(),
        }
    }

    /// Returns the DOS header.
    pub fn dos_header(&self) -> Result<&ImageDosHeader, VmiError> {
        Ok(self.pe()?.dos_header())
    }

    /// Returns the NT headers.
    pub fn nt_headers(&self) -> Result<&ImageNtHeaders, VmiError> {
        Ok(self.pe()?.nt_headers())
    }

    /// Returns the debug directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]`.
    pub fn debug_directory(&'a self) -> Result<Option<PeDebugDirectory<'a, Driver>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;

        Ok(Some(PeDebugDirectory::new(self, entry, data)))
    }

    /// Returns the export directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]`.
    pub fn export_directory(&self) -> Result<Option<PeExportDirectory<Driver>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;

        Ok(Some(PeExportDirectory::new(self, entry, data)))
    }

    /// Finds the specified data directory entry.
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

    /// Reads the contents of a data directory entry.
    fn read_data_directory(&self, entry: &ImageDataDirectory) -> Result<Vec<u8>, VmiError> {
        let mut data = vec![0; entry.size.get(LE) as usize];
        self.vmi
            .read(self.va + entry.virtual_address.get(LE) as u64, &mut data)?;

        Ok(data)
    }

    /// Returns the parsed PE representation of the image.
    fn pe(&self) -> Result<&Pe, VmiError> {
        self.pe.get_or_try_init(|| {
            let mut data = vec![0; Driver::Architecture::PAGE_SIZE as usize];
            self.vmi.read(self.va, &mut data)?;
            Ok(Pe::new(&data).map_err(WindowsError::from)?)
        })
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for WindowsImage<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the base address of the image.
    fn base_address(&self) -> Va {
        self.va
    }

    /// Returns the target architecture for which the image was compiled.
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        match self.pe()?.nt_headers().optional_header() {
            ImageOptionalHeader::ImageOptionalHeader32(_) => Ok(Some(VmiOsImageArchitecture::X86)),
            ImageOptionalHeader::ImageOptionalHeader64(_) => {
                Ok(Some(VmiOsImageArchitecture::Amd64))
            }
        }
    }

    /// Returns the exported symbols.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError> {
        let directory = match self.export_directory()? {
            Some(directory) => directory,
            None => return Ok(Vec::new()),
        };

        let exports = directory.exports().map_err(WindowsError::from)?;

        Ok(exports
            .into_iter()
            .filter_map(|export| match export.target {
                ExportTarget::Address(address) => Some(VmiOsImageSymbol {
                    name: String::from_utf8_lossy(export.name?).to_string(),
                    address: self.va + address as u64,
                }),
                _ => None,
            })
            .collect())
    }
}
