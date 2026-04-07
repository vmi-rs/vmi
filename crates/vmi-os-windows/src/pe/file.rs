//! File-backed PE image implementation.

use object::{
    endian::LittleEndian as LE,
    pe::{
        IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
        ImageDataDirectory, ImageSectionHeader,
    },
    read::ReadRef as _,
};
use vmi_core::VmiError;

use super::{
    ImageDosHeader, ImageNtHeaders, PeDebugDirectory, PeError, PeExceptionDirectory,
    PeExportDirectory, PeHeader, PeImage,
};
use crate::WindowsError;

/// A PE image backed by file data.
///
/// Reads PE structures from a byte buffer rather than VMI memory.
pub struct PeFile<'data> {
    pe_header: PeHeader,
    data: &'data [u8],
    sections: &'data [ImageSectionHeader],
}

impl<'data> PeFile<'data> {
    /// Creates a new `PeFile` from raw PE data.
    pub fn new(data: &'data [u8]) -> Result<Self, PeError> {
        let pe_header = PeHeader::parse(data)?;

        let section_table_offset = pe_header.section_table_offset();
        let number_of_sections = pe_header.nt_headers().file_header().number_of_sections() as usize;

        let sections = data
            .read_slice_at(section_table_offset, number_of_sections)
            .map_err(|_| PeError::InvalidSectionTable)?;

        Ok(Self {
            pe_header,
            data,
            sections,
        })
    }

    /// Finds the specified data directory entry.
    fn find_data_directory(&self, index: usize) -> Result<Option<ImageDataDirectory>, VmiError> {
        let entry = match self.pe_header.data_directories().get(index).copied() {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if entry.virtual_address.get(LE) == 0 || entry.size.get(LE) == 0 {
            return Ok(None);
        }

        Ok(Some(entry))
    }

    /// Reads the contents of a data directory entry.
    fn read_data_directory(&self, entry: &ImageDataDirectory) -> Result<Vec<u8>, VmiError> {
        let mut data = vec![0; entry.size.get(LE) as usize];
        self.read_at_rva(entry.virtual_address.get(LE), &mut data)?;
        Ok(data)
    }
}

impl PeImage for PeFile<'_> {
    fn read_at_rva(&self, rva: u32, buf: &mut [u8]) -> Result<(), VmiError> {
        // Try reading from a section (handles RVA-to-file-offset translation).
        for section in self.sections {
            if let Some(section_data) = section.pe_data_at(self.data, rva)
                && section_data.len() >= buf.len()
            {
                buf.copy_from_slice(&section_data[..buf.len()]);
                return Ok(());
            }
        }

        // Fall back to the header region where RVA == file offset.
        let start = rva as usize;
        let end = start + buf.len();
        if end <= self.data.len() {
            buf.copy_from_slice(&self.data[start..end]);
            return Ok(());
        }

        Err(VmiError::Os(Box::new(WindowsError::Pe(
            PeError::InvalidRva(rva),
        ))))
    }

    fn dos_header(&self) -> Result<&ImageDosHeader, VmiError> {
        Ok(self.pe_header.dos_header())
    }

    fn nt_headers(&self) -> Result<&ImageNtHeaders, VmiError> {
        Ok(self.pe_header.nt_headers())
    }

    fn export_directory(&self) -> Result<Option<PeExportDirectory<'_, Self>>, VmiError> {
        let entry = match self.find_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let data = self.read_data_directory(&entry)?;
        Ok(Some(PeExportDirectory::new(self, entry, data)))
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
}
