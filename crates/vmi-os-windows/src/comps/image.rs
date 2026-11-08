use std::ops::Range;

use once_cell::unsync::OnceCell;
use vmi_core::{
    Architecture, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{NoOS, VmiOsImage, VmiOsImageArchitecture, VmiOsImageSymbol},
};
use zerocopy::{FromZeros as _, IntoBytes as _};

use crate::{
    ArchAdapter, WindowsError, WindowsOs,
    pe::{
        ExportTarget, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, ImageDataDirectory,
        ImageDosHeader, ImageNtHeaders, ImageOptionalHeader, ImageSectionHeader, PeDebugDirectory,
        PeDelayImportDirectory, PeError, PeExceptionDirectory, PeExportDirectory, PeHeader,
        PeIatDirectory, PeImage, PeImportDirectory, PeLoadConfigDirectory,
    },
};

/// A Windows executable image (PE).
///
/// A Windows image is an executable or DLL mapped into memory.
pub struct WindowsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state (without the OS context).
    ///
    /// The OS context is omitted so that the image can be used
    /// in [`ArchAdapter::find_kernel`], where the OS context is
    /// not available.
    pub(crate) vmi: VmiState<'a, NoOS<Driver>>,

    /// The base address of the image.
    va: Va,

    /// Cached PE header.
    pe_header: OnceCell<PeHeader>,

    /// Cached section table.
    sections: OnceCell<Vec<ImageSectionHeader>>,
}

impl<Driver> VmiVa for WindowsImage<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    const MAX_DATA_DIRECTORY_SIZE: u32 = 1024 * 1024; // 1MB

    /// Creates a new Windows image.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self::new_without_os(vmi.without_os(), va)
    }

    /// Creates a new Windows image without the OS context.
    pub(crate) fn new_without_os(vmi: VmiState<'a, NoOS<Driver>>, va: Va) -> Self {
        Self {
            vmi,
            va,
            pe_header: OnceCell::new(),
            sections: OnceCell::new(),
        }
    }

    /// Finds the specified data directory entry.
    fn find_data_directory(&self, index: usize) -> Result<Option<ImageDataDirectory>, VmiError> {
        let entry = match self.pe()?.data_directories().get(index).copied() {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if entry.virtual_address == 0
            || entry.size == 0
            || entry.size > Self::MAX_DATA_DIRECTORY_SIZE
        {
            return Ok(None);
        }

        Ok(Some(entry))
    }

    /// Reads the contents of a data directory entry.
    fn read_data_directory(&self, entry: &ImageDataDirectory) -> Result<Vec<u8>, VmiError> {
        let mut data = vec![0; entry.size as usize];
        self.vmi
            .read(self.va + entry.virtual_address as u64, &mut data)?;

        Ok(data)
    }

    /// Returns the parsed PE representation of the image.
    fn pe(&self) -> Result<&PeHeader, VmiError> {
        self.pe_header.get_or_try_init(|| {
            let mut data = vec![0; Driver::Architecture::PAGE_SIZE as usize];
            self.vmi.read(self.va, &mut data)?;
            Ok(PeHeader::parse(&data).map_err(WindowsError::from)?)
        })
    }

    /// Returns the section table, which the first call reads.
    fn sections(&self) -> Result<&[ImageSectionHeader], VmiError> {
        let sections = self.sections.get_or_try_init(|| -> Result<_, VmiError> {
            let pe_header = self.pe()?;
            let nt_headers = pe_header.nt_headers();

            let section_table_offset = pe_header.section_table_offset();
            let number_of_sections = nt_headers.file_header.number_of_sections as usize;

            if number_of_sections * size_of::<ImageSectionHeader>()
                > Self::MAX_DATA_DIRECTORY_SIZE as usize
            {
                return Err(WindowsError::from(PeError::InvalidSectionTable).into());
            }

            let mut sections = vec![ImageSectionHeader::new_zeroed(); number_of_sections];
            self.vmi
                .read(self.va + section_table_offset, sections.as_mut_bytes())?;

            Ok(sections)
        })?;

        Ok(sections)
    }

    /// Returns the RVAs of the section that holds `rva`, or `None` when no
    /// section holds it.
    ///
    /// A section takes its `VirtualSize` from its `VirtualAddress` on, or
    /// its `SizeOfRawData` when `VirtualSize` is 0.
    fn section_range(&self, rva: u32) -> Result<Option<Range<u32>>, VmiError> {
        for section in self.sections()? {
            let size = if section.virtual_size != 0 {
                section.virtual_size
            }
            else {
                section.size_of_raw_data
            };

            let range = section.virtual_address..section.virtual_address.saturating_add(size);
            if range.contains(&rva) {
                return Ok(Some(range));
            }
        }

        Ok(None)
    }

    /// Reads the bytes at the RVAs of `range`, or returns `None` when the
    /// range takes more than `MAX_DATA_DIRECTORY_SIZE` bytes.
    fn read_range(&self, range: Range<u32>) -> Result<Option<Vec<u8>>, VmiError> {
        if range.len() > Self::MAX_DATA_DIRECTORY_SIZE as usize {
            return Ok(None);
        }

        let mut data = vec![0; range.len()];
        self.vmi.read(self.va + range.start as u64, &mut data)?;

        Ok(Some(data))
    }
}

impl<'a, Driver> PeImage for WindowsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn read_at_rva(&self, rva: u32, buf: &mut [u8]) -> Result<(), VmiError> {
        self.vmi.read(self.va + rva as u64, buf)
    }

    fn dos_header(&self) -> Result<&ImageDosHeader, VmiError> {
        Ok(self.pe()?.dos_header())
    }

    fn nt_headers(&self) -> Result<&ImageNtHeaders, VmiError> {
        Ok(self.pe()?.nt_headers())
    }

    fn export_directory(&self) -> Result<Option<PeExportDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;
        Ok(Some(PeExportDirectory::new(self, entry, data)))
    }

    fn import_directory(&self) -> Result<Option<PeImportDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let section = match self.section_range(entry.virtual_address)? {
            Some(section) => section,
            None => return Err(WindowsError::from(PeError::InvalidImportTable).into()),
        };

        let data = match self.read_range(entry.virtual_address..section.end)? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeImportDirectory::new(self, entry, data)?))
    }

    fn exception_directory(&self) -> Result<Option<PeExceptionDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;
        Ok(Some(PeExceptionDirectory::new(self, data)))
    }

    fn debug_directory(&self) -> Result<Option<PeDebugDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;
        Ok(Some(PeDebugDirectory::new(self, data)))
    }

    fn load_config_directory(&self) -> Result<Option<PeLoadConfigDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        Ok(Some(PeLoadConfigDirectory::new(self, entry)?))
    }

    fn iat_directory(&self) -> Result<Option<PeIatDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_IAT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        Ok(Some(PeIatDirectory::new(self, entry)))
    }

    fn delay_import_directory(&self) -> Result<Option<PeDelayImportDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let section = match self.section_range(entry.virtual_address)? {
            Some(section) => section,
            None => return Err(WindowsError::from(PeError::InvalidDelayImportTable).into()),
        };

        let data = match self.read_range(section.clone())? {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some(PeDelayImportDirectory::new(
            self,
            entry,
            section.start,
            data,
        )?))
    }
}

impl<'a, Driver> VmiOsImage<'a, Driver> for WindowsImage<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the base address of the image.
    fn base_address(&self) -> Va {
        self.va
    }

    /// Returns the target architecture for which the image was compiled.
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError> {
        let nt_headers = self.pe()?.nt_headers();

        match &nt_headers.optional_header {
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
