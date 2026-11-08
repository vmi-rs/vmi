//! Portable Executable (PE) parsing.
//!
//! Parses PE/COFF binaries from VMI memory or file buffers, exposing the
//! DOS and NT headers, the data directory array, and the standard export,
//! import, debug, exception, load configuration, import address table and
//! delay-load import directory layouts.

mod error;
mod file;
mod headers;
#[cfg(test)]
mod tests;

pub use isr_dl_windows::CodeView; // Intentional re-export.
use vmi_core::{Va, VmiError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use self::headers::{
    DelayLoadImportTable, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, ImportTable, LoadConfigLayout,
};
pub use self::{
    error::PeError,
    file::PeFile,
    headers::{
        Export, ExportTable, ExportTarget, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DELAYLOAD_RVA_BASED,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, IMAGE_DIRECTORY_ENTRY_BASERELOC,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
        IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_RESOURCE,
        IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_SIGNATURE,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory, ImageDebugDirectory,
        ImageDelayloadDescriptor, ImageDosHeader, ImageFileHeader, ImageImportDescriptor,
        ImageNtHeaders, ImageOptionalHeader, ImageOptionalHeader32, ImageOptionalHeader64,
        ImageRuntimeFunctionEntry, ImageSectionHeader, Import,
    },
};

/// Trait for reading PE image data.
///
/// Abstracts the source of PE data - either VMI memory ([`WindowsImage`])
/// or a local file buffer ([`PeFile`]). Directory accessors are provided
/// as default methods.
///
/// [`WindowsImage`]: crate::WindowsImage
pub trait PeImage: Sized {
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

    /// Returns the import directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`.
    fn import_directory(&self) -> Result<Option<PeImportDirectory<'_, Self>>, VmiError>;

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

    /// Returns the load configuration directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]`.
    fn load_config_directory(&self) -> Result<Option<PeLoadConfigDirectory<'_, Self>>, VmiError>;

    /// Returns the import address table directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]`.
    fn iat_directory(&self) -> Result<Option<PeIatDirectory<'_, Self>>, VmiError>;

    /// Returns the delay-load import directory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]`.
    fn delay_import_directory(&self) -> Result<Option<PeDelayImportDirectory<'_, Self>>, VmiError>;
}

/// Extension methods on [`PeImage`].
pub trait PeImageExt: PeImage {
    /// Returns the CodeView debug information.
    ///
    /// The [`CodeView`] debug information is located in the debug directory
    /// with type [`IMAGE_DEBUG_TYPE_CODEVIEW`].
    ///
    /// Shortcut for [`self.debug_directory()?.codeview()`].
    ///
    /// [`self.debug_directory()?.codeview()`]: PeDebugDirectory::codeview
    fn codeview(&self) -> Result<Option<CodeView>, VmiError> {
        let debug_directory = match self.debug_directory()? {
            Some(debug_directory) => debug_directory,
            None => return Ok(None),
        };

        debug_directory.codeview()
    }
}

impl<T> PeImageExt for T where T: PeImage {}

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
    ///
    /// # Notes
    ///
    /// An export whose forwarder string does not parse is left out. Windows
    /// 7's `shlwapi.dll` has one, which forwards to
    /// `SHUNIMPL.#UNIMPL_SHCreateStreamWrapper` with a name after the `#`
    /// that marks an ordinal.
    pub fn exports(&self) -> Result<Vec<Export<'_>>, PeError> {
        let export_table = ExportTable::parse(&self.data, self.entry.virtual_address)
            .map_err(|_| PeError::InvalidExportTable)?;

        // `ExportTable::exports` fails on such a forwarder, so the exports
        // are read here one by one.
        let mut exports = export_table
            .address_iter()
            .map(|(_index, ordinal, address)| {
                let target = export_table.target_from_address(address).ok()?;
                Some(Export {
                    ordinal,
                    name: None,
                    target,
                })
            })
            .collect::<Vec<_>>();

        for (name_pointer, index) in export_table.name_iter() {
            let name = export_table
                .name_from_pointer(name_pointer)
                .map_err(|_| PeError::InvalidExportTable)?;

            match exports.get_mut(usize::from(index.0)) {
                Some(Some(export)) => export.name = Some(name),
                Some(None) => {}
                None => return Err(PeError::InvalidExportTable),
            }
        }

        Ok(exports.into_iter().flatten().collect())
    }
}

/// PE import directory accessor.
///
/// The import directory holds one descriptor for each DLL whose exports the
/// image imports. A descriptor's import name table gives the name or the
/// ordinal of each import. The descriptor's import address table holds the
/// import's address at the same index. The loader writes the addresses when
/// it loads the image.
///
/// # Notes
///
/// The accessor reads the bytes from the descriptors to the end of the
/// section that holds them when it is created. Its methods look for the
/// import name tables and the names in those bytes only, and fail with
/// [`PeError::InvalidImportTable`] for one that lies elsewhere. A read of a
/// page that is not present fails with [`VmiError::Translation`].
///
/// # Implementation Details
///
/// Corresponds to
/// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`.
pub struct PeImportDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Data directory entry of the import descriptors.
    entry: ImageDataDirectory,

    /// Raw bytes from the descriptors to the end of their section.
    data: Vec<u8>,

    /// Size of an import name table entry, which is 4 bytes in a 32-bit
    /// image and 8 bytes in a 64-bit image.
    thunk_size: usize,

    /// The image's `SizeOfImage`.
    size_of_image: u32,
}

impl<'a, Image: PeImage> PeImportDirectory<'a, Image> {
    /// Creates a new PE import directory accessor.
    ///
    /// `data` holds the bytes from the entry's RVA to the end of the section
    /// that holds it. The size of an import name table entry and
    /// `SizeOfImage` come from the image's optional header.
    pub(crate) fn new(
        image: &'a Image,
        entry: ImageDataDirectory,
        data: Vec<u8>,
    ) -> Result<Self, VmiError> {
        let nt_headers = image.nt_headers()?;
        let optional_header = &nt_headers.optional_header;

        Ok(Self {
            image,
            entry,
            data,
            thunk_size: Thunk::size(optional_header),
            size_of_image: optional_header.size_of_image(),
        })
    }

    /// Returns the import descriptors, without the descriptor that ends the
    /// array.
    ///
    /// # Notes
    ///
    /// The walk ends at the first descriptor whose `Name` or `FirstThunk`
    /// is 0. Windows' loader ends its walk at the same descriptor. The
    /// directory's size bounds neither walk. The walk fails with
    /// [`PeError::InvalidImportTable`] when the bytes end before that
    /// descriptor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the array of `_IMAGE_IMPORT_DESCRIPTOR` at the
    /// directory's RVA.
    pub fn descriptors(&self) -> Result<&[ImageImportDescriptor], PeError> {
        let (descriptors, _) = <[ImageImportDescriptor]>::ref_from_prefix_with_elems(
            &self.data,
            self.data.len() / size_of::<ImageImportDescriptor>(),
        )
        .map_err(|_| PeError::InvalidImportTable)?;

        match descriptors
            .iter()
            .position(|descriptor| descriptor.name == 0 || descriptor.first_thunk == 0)
        {
            Some(count) => Ok(&descriptors[..count]),
            None => Err(PeError::InvalidImportTable),
        }
    }

    /// Returns the name of a descriptor's DLL, without its terminating NUL.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the string at `_IMAGE_IMPORT_DESCRIPTOR.Name`.
    pub fn name(&self, descriptor: &ImageImportDescriptor) -> Result<&[u8], PeError> {
        self.table()
            .name(descriptor.name)
            .map_err(|_| PeError::InvalidImportTable)
    }

    /// Returns an import of a descriptor, or `None` at the entry that ends
    /// the import name table and for a descriptor without that table.
    ///
    /// `index` picks the entry of the descriptor's import name table. The
    /// descriptor's import address table holds the import's address at the
    /// same index, in the slot at `first_thunk` plus `index` times the size
    /// of an address. An address takes 4 bytes in a 32-bit image and 8 bytes
    /// in a 64-bit image.
    ///
    /// # Notes
    ///
    /// Some linkers write no import name table. A descriptor without the
    /// table holds 0 in `original_first_thunk`, or an RVA past the image's
    /// `SizeOfImage`, and Windows' loader then takes the names from the
    /// import address table. In a loaded image that table holds addresses
    /// instead of the names.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to an `IMAGE_THUNK_DATA32` or `IMAGE_THUNK_DATA64` of the
    /// array at `_IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk`, and to the
    /// `IMAGE_IMPORT_BY_NAME` that an import by name points to.
    pub fn import(
        &self,
        descriptor: &ImageImportDescriptor,
        index: usize,
    ) -> Result<Option<Import<'_>>, PeError> {
        let table_rva = descriptor.original_first_thunk;
        if table_rva == 0 || table_rva >= self.size_of_image {
            return Ok(None);
        }

        Thunk::read(
            &self.data,
            self.entry.virtual_address,
            table_rva,
            index,
            self.thunk_size,
        )
        .ok_or(PeError::InvalidImportTable)?
        .import(|rva| self.table().hint_name(rva))
        .map_err(|_| PeError::InvalidImportTable)
    }

    /// Returns `object`'s parser of the import table, over the bytes that the
    /// accessor read.
    fn table(&self) -> ImportTable<'_> {
        ImportTable::new(
            &self.data,
            self.entry.virtual_address,
            self.entry.virtual_address,
        )
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
            tracing::warn!("invalid CodeView Info size");
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
                tracing::warn!(%err, "invalid CodeView Info address");
                return Ok(None);
            }
        };

        if info.signature != CV_SIGNATURE_RSDS {
            tracing::warn!("invalid CodeView signature");
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

/// PE load configuration directory accessor.
///
/// Holds the image's `IMAGE_LOAD_CONFIG_DIRECTORY32` or
/// `IMAGE_LOAD_CONFIG_DIRECTORY64`. Linkers write newer versions of the
/// structure with more fields, and the structure's `Size` field says which
/// of them an image has.
///
/// # Implementation Details
///
/// Corresponds to
/// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]`.
pub struct PeLoadConfigDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Field offsets of the structure for the image's bitness.
    layout: &'static LoadConfigLayout,

    /// The structure's `Size` field.
    size: u32,

    /// Raw bytes read at the directory's RVA, as many as `size` gives and
    /// at most the whole structure.
    data: Vec<u8>,
}

impl<'a, Image: PeImage> PeLoadConfigDirectory<'a, Image> {
    /// Creates a new PE load configuration directory parser.
    ///
    /// Reads the structure at the entry's RVA. The structure's `Size` field
    /// gives the number of bytes to read, at most the whole structure. The
    /// entry's own size plays no part. An older image can give less there,
    /// such as 0x40 bytes for a structure of 0x48 bytes in the 32-bit
    /// `ntdll.dll` of Windows 7 SP1.
    pub(crate) fn new(image: &'a Image, entry: ImageDataDirectory) -> Result<Self, VmiError> {
        let layout = match image.nt_headers()?.optional_header {
            ImageOptionalHeader::ImageOptionalHeader32(_) => &LoadConfigLayout::DIRECTORY32,
            ImageOptionalHeader::ImageOptionalHeader64(_) => &LoadConfigLayout::DIRECTORY64,
        };

        let size = image.read_struct_at_rva::<u32>(entry.virtual_address)?;
        let mut data = vec![0; std::cmp::min(size as usize, layout.size)];
        image.read_at_rva(entry.virtual_address, &mut data)?;

        Ok(Self {
            image,
            layout,
            size,
            data,
        })
    }

    /// Returns the size of the directory in bytes.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `IMAGE_LOAD_CONFIG_DIRECTORY64.Size`.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Returns the address of the slot that holds the check routine of
    /// Control Flow Guard, or `None` if the directory is too short for it.
    ///
    /// # Notes
    ///
    /// The loader writes the routine into the slot before the image's code
    /// runs. Read the slot to find the routine.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardCFCheckFunctionPointer`.
    pub fn guard_cf_check_function_pointer(&self) -> Option<Va> {
        self.address(self.layout.guard_cf_check_function_pointer)
    }

    /// Returns the address of the slot that holds the dispatch routine of
    /// Control Flow Guard, or `None` if the directory is too short for it.
    ///
    /// # Notes
    ///
    /// The loader writes the routine into the slot before the image's code
    /// runs. Read the slot to find the routine.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardCFDispatchFunctionPointer`.
    pub fn guard_cf_dispatch_function_pointer(&self) -> Option<Va> {
        self.address(self.layout.guard_cf_dispatch_function_pointer)
    }

    /// Returns the flags of Control Flow Guard, or `None` if the directory
    /// is too short for them.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags`.
    pub fn guard_flags(&self) -> Option<u32> {
        let offset = self.layout.guard_flags;
        let field = self.data.get(offset..offset + size_of::<u32>())?;
        Some(u32::from_le_bytes(field.try_into().ok()?))
    }

    /// Returns the address of the slot that holds the XFG check routine, or
    /// `None` if the directory is too short for it.
    ///
    /// # Notes
    ///
    /// The loader writes the routine into the slot before the image's code
    /// runs. Read the slot to find the routine.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardXFGCheckFunctionPointer`.
    pub fn guard_xfg_check_function_pointer(&self) -> Option<Va> {
        self.address(self.layout.guard_xfg_check_function_pointer)
    }

    /// Returns the address of the slot that holds the XFG dispatch routine,
    /// or `None` if the directory is too short for it.
    ///
    /// # Notes
    ///
    /// The loader writes the routine into the slot before the image's code
    /// runs. Read the slot to find the routine.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardXFGDispatchFunctionPointer`.
    pub fn guard_xfg_dispatch_function_pointer(&self) -> Option<Va> {
        self.address(self.layout.guard_xfg_dispatch_function_pointer)
    }

    /// Returns the address of the slot that holds the XFG table dispatch
    /// routine, or `None` if the directory is too short for it.
    ///
    /// # Notes
    ///
    /// The loader writes the routine into the slot before the image's code
    /// runs. Read the slot to find the routine.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardXFGTableDispatchFunctionPointer`.
    pub fn guard_xfg_table_dispatch_function_pointer(&self) -> Option<Va> {
        self.address(self.layout.guard_xfg_table_dispatch_function_pointer)
    }

    /// Returns the address in the field at `offset`, or `None` if the field
    /// does not fit in the bytes read.
    fn address(&self, offset: usize) -> Option<Va> {
        let field = self.data.get(offset..offset + self.layout.address_size)?;

        // A 32-bit image stores 4 bytes, which zero-extend to the address.
        let mut address = [0; size_of::<u64>()];
        address[..field.len()].copy_from_slice(field);
        Some(Va(u64::from_le_bytes(address)))
    }
}

/// PE import address table directory accessor.
///
/// The import address tables hold the addresses of the imported functions,
/// which the loader writes when it loads the image.
///
/// # Notes
///
/// The accessor reads only the data directory entry, not the tables, so it
/// works while the tables are paged out.
///
/// # Implementation Details
///
/// Corresponds to
/// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]`.
pub struct PeIatDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Data directory entry of the import address tables.
    entry: ImageDataDirectory,
}

impl<'a, Image: PeImage> PeIatDirectory<'a, Image> {
    /// Creates a new PE import address table directory accessor.
    pub(crate) fn new(image: &'a Image, entry: ImageDataDirectory) -> Self {
        Self { image, entry }
    }

    /// Returns the RVA of the import address tables.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `IMAGE_DATA_DIRECTORY.VirtualAddress`.
    pub fn virtual_address(&self) -> u32 {
        self.entry.virtual_address
    }

    /// Returns the size of the tables in bytes.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `IMAGE_DATA_DIRECTORY.Size`.
    pub fn size(&self) -> u32 {
        self.entry.size
    }
}

/// PE delay-load import directory accessor.
///
/// The delay-load import directory holds one descriptor for each DLL that
/// the image loads at the first call of one of its imports. A descriptor's
/// import name table gives the name or the ordinal of each import. The
/// descriptor's import address table holds the import's slot at the same
/// index. A resolver, such as `ResolveDelayLoadedAPI`, writes the import's
/// address into the slot at the first call.
///
/// # Notes
///
/// The accessor reads the whole section that holds the descriptors when it
/// is created. Its methods look for the import name tables and the names in
/// that section only, and fail with [`PeError::InvalidDelayImportTable`] for
/// one that lies elsewhere. A read of a page that is not present fails with
/// [`VmiError::Translation`].
///
/// A descriptor without `IMAGE_DELAYLOAD_RVA_BASED` in its attributes holds
/// addresses instead of RVAs. `name` and `import` fail for such a
/// descriptor with [`PeError::InvalidDelayImportTable`].
///
/// # Implementation Details
///
/// Corresponds to
/// `_IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]`.
pub struct PeDelayImportDirectory<'a, Image: PeImage> {
    /// Owning image.
    #[expect(unused)]
    image: &'a Image,

    /// Data directory entry of the delay-load descriptors.
    entry: ImageDataDirectory,

    /// RVA of the section that holds the descriptors.
    section_address: u32,

    /// Raw bytes of that section.
    data: Vec<u8>,

    /// Size of an import name table entry, which is 4 bytes in a 32-bit
    /// image and 8 bytes in a 64-bit image.
    thunk_size: usize,
}

impl<'a, Image: PeImage> PeDelayImportDirectory<'a, Image> {
    /// Creates a new PE delay-load import directory accessor.
    ///
    /// `data` holds the section that starts at `section_address` and holds
    /// the entry's RVA. The size of an import name table entry comes from
    /// the image's optional header.
    pub(crate) fn new(
        image: &'a Image,
        entry: ImageDataDirectory,
        section_address: u32,
        data: Vec<u8>,
    ) -> Result<Self, VmiError> {
        let thunk_size = Thunk::size(&image.nt_headers()?.optional_header);

        Ok(Self {
            image,
            entry,
            section_address,
            data,
            thunk_size,
        })
    }

    /// Returns the delay-load descriptors, without the descriptor that ends
    /// the array.
    ///
    /// # Notes
    ///
    /// The walk ends at the first descriptor whose fields are all 0, as the
    /// walk of `object`'s `DelayLoadImportTable` does. The directory's size
    /// does not bound it. The walk fails with
    /// [`PeError::InvalidDelayImportTable`] when the section ends before
    /// that descriptor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the array of `_IMAGE_DELAYLOAD_DESCRIPTOR` at the
    /// directory's RVA.
    pub fn descriptors(&self) -> Result<&[ImageDelayloadDescriptor], PeError> {
        let data = self
            .entry
            .virtual_address
            .checked_sub(self.section_address)
            .and_then(|offset| self.data.get(offset as usize..))
            .ok_or(PeError::InvalidDelayImportTable)?;

        let (descriptors, _) = <[ImageDelayloadDescriptor]>::ref_from_prefix_with_elems(
            data,
            data.len() / size_of::<ImageDelayloadDescriptor>(),
        )
        .map_err(|_| PeError::InvalidDelayImportTable)?;

        match descriptors
            .iter()
            .position(|descriptor| descriptor.as_bytes().iter().all(|byte| *byte == 0))
        {
            Some(count) => Ok(&descriptors[..count]),
            None => Err(PeError::InvalidDelayImportTable),
        }
    }

    /// Returns the name of a descriptor's DLL, without its terminating NUL.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the string at `_IMAGE_DELAYLOAD_DESCRIPTOR.DllNameRVA`.
    pub fn name(&self, descriptor: &ImageDelayloadDescriptor) -> Result<&[u8], PeError> {
        if descriptor.attributes & IMAGE_DELAYLOAD_RVA_BASED == 0 {
            return Err(PeError::InvalidDelayImportTable);
        }

        self.table()
            .name(descriptor.dll_name_rva)
            .map_err(|_| PeError::InvalidDelayImportTable)
    }

    /// Returns an import of a descriptor, or `None` at the entry that ends
    /// the import name table.
    ///
    /// `index` picks the entry of the descriptor's import name table. The
    /// descriptor's import address table holds the import's slot at the same
    /// index, at `import_address_table_rva` plus `index` times the size of
    /// an address.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to an `IMAGE_THUNK_DATA32` or `IMAGE_THUNK_DATA64` of the
    /// array at `_IMAGE_DELAYLOAD_DESCRIPTOR.ImportNameTableRVA`, and to the
    /// `IMAGE_IMPORT_BY_NAME` that an import by name points to.
    pub fn import(
        &self,
        descriptor: &ImageDelayloadDescriptor,
        index: usize,
    ) -> Result<Option<Import<'_>>, PeError> {
        if descriptor.attributes & IMAGE_DELAYLOAD_RVA_BASED == 0 {
            return Err(PeError::InvalidDelayImportTable);
        }

        Thunk::read(
            &self.data,
            self.section_address,
            descriptor.import_name_table_rva,
            index,
            self.thunk_size,
        )
        .ok_or(PeError::InvalidDelayImportTable)?
        .import(|rva| self.table().hint_name(rva))
        .map_err(|_| PeError::InvalidDelayImportTable)
    }

    /// Returns `object`'s parser of the delay-load import table, over the
    /// bytes that the accessor read.
    fn table(&self) -> DelayLoadImportTable<'_> {
        DelayLoadImportTable::new(&self.data, self.section_address, self.entry.virtual_address)
    }
}

/// An entry of an import name table.
///
/// # Implementation Details
///
/// Corresponds to an `IMAGE_THUNK_DATA32` or `IMAGE_THUNK_DATA64`.
enum Thunk {
    /// The entry that ends the table.
    End,

    /// An import by ordinal, with the ordinal from the entry's low 16 bits.
    Ordinal(u16),

    /// An import by name, with the RVA of its `IMAGE_IMPORT_BY_NAME`.
    Name(u32),
}

impl Thunk {
    /// Returns the size of an entry in an image with `optional_header`,
    /// which is 4 bytes in a 32-bit image and 8 bytes in a 64-bit image.
    fn size(optional_header: &ImageOptionalHeader) -> usize {
        match optional_header {
            ImageOptionalHeader::ImageOptionalHeader32(_) => size_of::<u32>(),
            ImageOptionalHeader::ImageOptionalHeader64(_) => size_of::<u64>(),
        }
    }

    /// Reads an entry of an import name table from `data`, or returns `None`
    /// when the entry lies outside `data`.
    ///
    /// `data` holds an image's bytes from the RVA `data_rva` on. The table
    /// starts at the RVA `table_rva`, `index` picks the entry, and `size` is
    /// the size of an entry.
    fn read(data: &[u8], data_rva: u32, table_rva: u32, index: usize, size: usize) -> Option<Self> {
        let offset =
            (table_rva.checked_sub(data_rva)? as usize).checked_add(index.checked_mul(size)?)?;
        let entry = data.get(offset..offset.checked_add(size)?)?;

        // A 32-bit image stores 4 bytes, which zero-extend to the entry.
        let mut value = [0; size_of::<u64>()];
        value[..entry.len()].copy_from_slice(entry);
        let value = u64::from_le_bytes(value);

        let ordinal_flag = if size == size_of::<u64>() {
            IMAGE_ORDINAL_FLAG64
        }
        else {
            u64::from(IMAGE_ORDINAL_FLAG32)
        };

        if value == 0 {
            Some(Self::End)
        }
        else if value & ordinal_flag != 0 {
            Some(Self::Ordinal(value as u16))
        }
        else {
            // The RVA takes the entry's low 31 bits.
            Some(Self::Name(value as u32 & 0x7fff_ffff))
        }
    }

    /// Returns the import that the entry gives, or `None` for the entry
    /// that ends the table.
    ///
    /// `hint_name` reads the hint and the name of an import by name at the
    /// RVA of its `IMAGE_IMPORT_BY_NAME`.
    fn import<'data, E>(
        self,
        hint_name: impl FnOnce(u32) -> Result<(u16, &'data [u8]), E>,
    ) -> Result<Option<Import<'data>>, E> {
        match self {
            Self::End => Ok(None),
            Self::Ordinal(ordinal) => Ok(Some(Import::Ordinal(ordinal))),
            Self::Name(rva) => {
                let (hint, name) = hint_name(rva)?;
                Ok(Some(Import::Name(hint, name)))
            }
        }
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
