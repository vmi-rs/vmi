//! Tests of the export, import, load configuration, import address table
//! and delay-load import directories on PE images built in a buffer.

use vmi_core::{Va, VmiError};
use zerocopy::{FromZeros as _, IntoBytes as _};

use super::{
    ExportTarget, IMAGE_DELAYLOAD_RVA_BASED, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageImportDescriptor,
    ImageOptionalHeader32, ImageOptionalHeader64, ImageSectionHeader, Import, PeError, PeFile,
    PeImage as _,
};
use crate::WindowsError;

/// The RVA of the directory in the built images.
const DIRECTORY_RVA: u32 = 0x200;

/// The RVA of the names that some tests put before the directory, after the
/// section table.
const NAMES_RVA: u32 = 0x180;

/// The `SizeOfImage` of the built images.
const SIZE_OF_IMAGE: u32 = 0x10000;

/// The ordinal flag of an import name table entry in a 32-bit image.
const ORDINAL_FLAG32: u64 = 0x8000_0000;

/// The ordinal flag of an import name table entry in a 64-bit image.
const ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Returns a PE image with `optional_header` and `sections`, and with the
/// directory of the data directory entry `index` at `DIRECTORY_RVA`.
///
/// The data directory entry gives the size `entry_size`, and `directory`
/// holds the directory's bytes. The section table follows the data
/// directories. Every RVA of the image is also the offset in the file, and
/// the sections of [`section`] keep it so.
fn image(
    optional_header: &[u8],
    sections: &[ImageSectionHeader],
    index: usize,
    entry_size: u32,
    directory: &[u8],
) -> Vec<u8> {
    let mut dos_header = ImageDosHeader::new_zeroed();
    dos_header.e_magic = IMAGE_DOS_SIGNATURE;
    dos_header.e_lfanew = size_of::<ImageDosHeader>() as u32;

    let mut data_directories = [ImageDataDirectory::new_zeroed(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    data_directories[index] = ImageDataDirectory {
        virtual_address: DIRECTORY_RVA,
        size: entry_size,
    };

    let mut file_header = ImageFileHeader::new_zeroed();
    file_header.number_of_sections = sections.len() as u16;
    file_header.size_of_optional_header =
        (optional_header.len() + data_directories.as_bytes().len()) as u16;

    let mut image = Vec::new();
    image.extend_from_slice(dos_header.as_bytes());
    image.extend_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
    image.extend_from_slice(file_header.as_bytes());
    image.extend_from_slice(optional_header);
    image.extend_from_slice(data_directories.as_bytes());
    image.extend_from_slice(sections.as_bytes());
    image.resize(DIRECTORY_RVA as usize, 0);
    image.extend_from_slice(directory);
    image
}

/// Returns a section that starts at `rva` and takes `size` bytes in memory
/// and in the file, at the offset in the file that equals its RVA.
fn section(rva: u32, size: u32) -> ImageSectionHeader {
    let mut section = ImageSectionHeader::new_zeroed();
    section.virtual_size = size;
    section.virtual_address = rva;
    section.size_of_raw_data = size;
    section.pointer_to_raw_data = rva;
    section
}

/// Returns the bytes of a PE32 optional header with every data directory
/// entry and `SIZE_OF_IMAGE`.
fn optional_header32() -> Vec<u8> {
    let mut header = ImageOptionalHeader32::new_zeroed();
    header.magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    header.size_of_image = SIZE_OF_IMAGE;
    header.number_of_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32;
    header.as_bytes().to_vec()
}

/// Returns the bytes of a PE32+ optional header with every data directory
/// entry and `SIZE_OF_IMAGE`.
fn optional_header64() -> Vec<u8> {
    let mut header = ImageOptionalHeader64::new_zeroed();
    header.magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    header.size_of_image = SIZE_OF_IMAGE;
    header.number_of_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32;
    header.as_bytes().to_vec()
}

/// Returns a load configuration directory of `length` bytes whose `Size`
/// field holds `size`.
///
/// Every other byte is 0xcc. A field read past `size` therefore gives a
/// value that no test expects.
fn directory(length: usize, size: u32) -> Vec<u8> {
    let mut directory = vec![0xcc; length];
    directory[..size_of::<u32>()].copy_from_slice(&size.to_le_bytes());
    directory
}

/// Writes `value` into `directory` at `offset`.
fn put(directory: &mut [u8], offset: usize, value: &[u8]) {
    directory[offset..offset + value.len()].copy_from_slice(value);
}

/// Returns the bytes of an import name table entry that holds `value`.
///
/// `thunk_size` is the size of an entry, which is 4 bytes in a 32-bit image
/// and 8 bytes in a 64-bit image.
fn thunk(thunk_size: usize, value: u64) -> Vec<u8> {
    value.to_le_bytes()[..thunk_size].to_vec()
}

/// Returns an import directory with its tables and names, at their offsets
/// from `DIRECTORY_RVA`.
///
/// The directory imports `CreateFileW` by name and the ordinal 7 from
/// `KERNEL32.dll`, and the ordinal 42 and `GetDC` by name from
/// `USER32.dll`. `thunk_size` is the size of an import name table entry,
/// and `ordinal_flag` marks an import by ordinal.
fn import_directory(thunk_size: usize, ordinal_flag: u64) -> Vec<u8> {
    let rva = |offset: u32| DIRECTORY_RVA + offset;
    let mut directory = vec![0; 0x100];

    // Two descriptors, each with its `OriginalFirstThunk`, `Name` and
    // `FirstThunk`, and the descriptor of zeros that ends the array.
    put(&mut directory, 0x00, &rva(0x40).to_le_bytes());
    put(&mut directory, 0x0c, &rva(0xc0).to_le_bytes());
    put(&mut directory, 0x10, &rva(0x80).to_le_bytes());
    put(&mut directory, 0x14, &rva(0x60).to_le_bytes());
    put(&mut directory, 0x20, &rva(0xd0).to_le_bytes());
    put(&mut directory, 0x24, &rva(0xa0).to_le_bytes());

    // The import name tables, each ended by an entry of zeros.
    put(&mut directory, 0x40, &thunk(thunk_size, rva(0xe0).into()));
    put(
        &mut directory,
        0x40 + thunk_size,
        &thunk(thunk_size, ordinal_flag | 7),
    );
    put(&mut directory, 0x60, &thunk(thunk_size, ordinal_flag | 42));
    put(
        &mut directory,
        0x60 + thunk_size,
        &thunk(thunk_size, rva(0xf0).into()),
    );

    // The DLL names, and the hints with the names of the imports by name.
    put(&mut directory, 0xc0, b"KERNEL32.dll\0");
    put(&mut directory, 0xd0, b"USER32.dll\0");
    put(&mut directory, 0xe0, &0x00d6_u16.to_le_bytes());
    put(&mut directory, 0xe2, b"CreateFileW\0");
    put(&mut directory, 0xf0, &0x0123_u16.to_le_bytes());
    put(&mut directory, 0xf2, b"GetDC\0");
    directory
}

/// Checks the imports of [`import_directory`] in an image with
/// `optional_header`, whose import name table entries take `thunk_size`
/// bytes and mark an import by ordinal with `ordinal_flag`.
fn check_imports(
    optional_header: &[u8],
    thunk_size: usize,
    ordinal_flag: u64,
) -> Result<(), VmiError> {
    let directory = import_directory(thunk_size, ordinal_flag);

    // The entry's size covers only the first descriptor. The walk reads
    // both.
    let image = image(
        optional_header,
        &[section(DIRECTORY_RVA, directory.len() as u32)],
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        size_of::<ImageImportDescriptor>() as u32,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let imports = file.import_directory()?.expect("import directory");
    let descriptors = imports.descriptors().map_err(WindowsError::from)?;

    assert_eq!(descriptors.len(), 2);
    assert_eq!(
        imports.name(&descriptors[0]).map_err(WindowsError::from)?,
        &b"KERNEL32.dll"[..]
    );
    assert_eq!(
        imports.name(&descriptors[1]).map_err(WindowsError::from)?,
        &b"USER32.dll"[..]
    );
    assert!(matches!(
        imports.import(&descriptors[0], 0),
        Ok(Some(Import::Name(0x00d6, b"CreateFileW")))
    ));
    assert!(matches!(
        imports.import(&descriptors[0], 1),
        Ok(Some(Import::Ordinal(7)))
    ));
    assert!(matches!(imports.import(&descriptors[0], 2), Ok(None)));
    assert!(matches!(
        imports.import(&descriptors[1], 0),
        Ok(Some(Import::Ordinal(42)))
    ));
    assert!(matches!(
        imports.import(&descriptors[1], 1),
        Ok(Some(Import::Name(0x0123, b"GetDC")))
    ));
    assert!(matches!(imports.import(&descriptors[1], 2), Ok(None)));

    Ok(())
}

#[test]
fn reads_guard_fields_of_64_bit_directory() -> Result<(), VmiError> {
    // `Size` ends after `GuardFlags`, before the XFG fields.
    let mut directory = directory(0x148, 0x94);
    put(&mut directory, 0x70, &0x1_4000_8850_u64.to_le_bytes());
    put(&mut directory, 0x78, &0x1_4000_8858_u64.to_le_bytes());
    put(&mut directory, 0x90, &0x1_0500_u32.to_le_bytes());

    // The entry gives 0x40 bytes, less than `Size`, as old images do.
    let image = image(
        &optional_header64(),
        &[],
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        0x40,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let load_config = file.load_config_directory()?.expect("load configuration");

    assert_eq!(load_config.size(), 0x94);
    assert_eq!(
        load_config.guard_cf_check_function_pointer(),
        Some(Va(0x1_4000_8850))
    );
    assert_eq!(
        load_config.guard_cf_dispatch_function_pointer(),
        Some(Va(0x1_4000_8858))
    );
    assert_eq!(load_config.guard_flags(), Some(0x1_0500));
    assert_eq!(load_config.guard_xfg_check_function_pointer(), None);
    assert_eq!(load_config.guard_xfg_dispatch_function_pointer(), None);
    assert_eq!(
        load_config.guard_xfg_table_dispatch_function_pointer(),
        None
    );

    Ok(())
}

#[test]
fn reads_guard_fields_of_32_bit_directory() -> Result<(), VmiError> {
    // `Size` ends after `GuardFlags`, before the XFG fields.
    let mut directory = directory(0xc4, 0x5c);
    put(&mut directory, 0x48, &0x0040_82d4_u32.to_le_bytes());
    put(&mut directory, 0x4c, &0x0040_82d8_u32.to_le_bytes());
    put(&mut directory, 0x58, &0x1_0500_u32.to_le_bytes());

    let image = image(
        &optional_header32(),
        &[],
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        0x5c,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let load_config = file.load_config_directory()?.expect("load configuration");

    assert_eq!(load_config.size(), 0x5c);
    assert_eq!(
        load_config.guard_cf_check_function_pointer(),
        Some(Va(0x0040_82d4))
    );
    assert_eq!(
        load_config.guard_cf_dispatch_function_pointer(),
        Some(Va(0x0040_82d8))
    );
    assert_eq!(load_config.guard_flags(), Some(0x1_0500));
    assert_eq!(load_config.guard_xfg_check_function_pointer(), None);
    assert_eq!(load_config.guard_xfg_dispatch_function_pointer(), None);
    assert_eq!(
        load_config.guard_xfg_table_dispatch_function_pointer(),
        None
    );

    Ok(())
}

#[test]
fn reads_xfg_fields_up_to_end_of_structure() -> Result<(), VmiError> {
    // `Size` goes past the end of the structure that the reader knows.
    let mut directory = directory(0x148, 0x200);
    put(&mut directory, 0x118, &0x1_8019_f008_u64.to_le_bytes());
    put(&mut directory, 0x120, &0x1_8019_f010_u64.to_le_bytes());
    put(&mut directory, 0x128, &0x1_8019_f018_u64.to_le_bytes());

    // The image ends with the structure. A read of `Size` bytes would fail.
    let image = image(
        &optional_header64(),
        &[],
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        0x200,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let load_config = file.load_config_directory()?.expect("load configuration");

    assert_eq!(load_config.size(), 0x200);
    assert_eq!(
        load_config.guard_xfg_check_function_pointer(),
        Some(Va(0x1_8019_f008))
    );
    assert_eq!(
        load_config.guard_xfg_dispatch_function_pointer(),
        Some(Va(0x1_8019_f010))
    );
    assert_eq!(
        load_config.guard_xfg_table_dispatch_function_pointer(),
        Some(Va(0x1_8019_f018))
    );

    Ok(())
}

#[test]
fn misses_field_that_size_cuts() -> Result<(), VmiError> {
    // `Size` ends in the middle of `GuardCFCheckFunctionPointer`.
    let directory = directory(0x148, 0x74);

    let image = image(
        &optional_header64(),
        &[],
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        0x74,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let load_config = file.load_config_directory()?.expect("load configuration");

    assert_eq!(load_config.size(), 0x74);
    assert_eq!(load_config.guard_cf_check_function_pointer(), None);
    assert_eq!(load_config.guard_cf_dispatch_function_pointer(), None);
    assert_eq!(load_config.guard_flags(), None);

    Ok(())
}

#[test]
fn locates_import_address_table_without_reading_it() -> Result<(), VmiError> {
    let image = image(
        &optional_header64(),
        &[],
        IMAGE_DIRECTORY_ENTRY_IAT,
        0x1000,
        &[],
    );

    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let iat = file.iat_directory()?.expect("import address table");

    assert_eq!(iat.virtual_address(), DIRECTORY_RVA);
    assert_eq!(iat.size(), 0x1000);
    Ok(())
}

#[test]
fn leaves_out_forwarder_that_does_not_parse() -> Result<(), VmiError> {
    // `IMAGE_EXPORT_DIRECTORY` with three functions and three names, then
    // the tables and the strings, at their offsets in the directory.
    let mut directory = vec![0; 0xd0];
    let rva = |offset: u32| (DIRECTORY_RVA + offset).to_le_bytes();
    put(&mut directory, 0x10, &1_u32.to_le_bytes());
    put(&mut directory, 0x14, &3_u32.to_le_bytes());
    put(&mut directory, 0x18, &3_u32.to_le_bytes());
    put(&mut directory, 0x1c, &rva(0x28));
    put(&mut directory, 0x20, &rva(0x34));
    put(&mut directory, 0x24, &rva(0x40));

    // A function, a forwarder with a name after `#`, as in Windows 7's
    // `shlwapi.dll`, and a forwarder by name.
    put(&mut directory, 0x28, &0x1000_u32.to_le_bytes());
    put(&mut directory, 0x2c, &rva(0x80));
    put(&mut directory, 0x30, &rva(0xb0));
    put(&mut directory, 0x34, &rva(0x50));
    put(&mut directory, 0x38, &rva(0x60));
    put(&mut directory, 0x3c, &rva(0x70));
    put(&mut directory, 0x40, &[0, 0, 1, 0, 2, 0]);
    put(&mut directory, 0x50, b"First\0");
    put(&mut directory, 0x60, b"Broken\0");
    put(&mut directory, 0x70, b"Forwarded\0");
    put(
        &mut directory,
        0x80,
        b"SHUNIMPL.#UNIMPL_SHCreateStreamWrapper\0",
    );
    put(&mut directory, 0xb0, b"NTDLL.RtlAllocateHeap\0");

    let image = image(
        &optional_header64(),
        &[],
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        directory.len() as u32,
        &directory,
    );
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let export_directory = file.export_directory()?.expect("export directory");
    let exports = export_directory.exports().map_err(WindowsError::from)?;

    assert_eq!(exports.len(), 2);
    assert_eq!(exports[0].ordinal.0, 1);
    assert_eq!(exports[0].name, Some(&b"First"[..]));
    assert!(matches!(exports[0].target, ExportTarget::Address(0x1000)));
    assert_eq!(exports[1].ordinal.0, 3);
    assert_eq!(exports[1].name, Some(&b"Forwarded"[..]));
    assert!(matches!(
        exports[1].target,
        ExportTarget::ForwardByName(b"NTDLL", b"RtlAllocateHeap")
    ));

    Ok(())
}

/// Returns an image with `optional_header` whose import directory holds
/// `directory`, in a section of its own.
fn import_image(optional_header: &[u8], directory: &[u8]) -> Vec<u8> {
    image(
        optional_header,
        &[section(DIRECTORY_RVA, directory.len() as u32)],
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        directory.len() as u32,
        directory,
    )
}

#[test]
fn reads_imports_of_32_bit_image() -> Result<(), VmiError> {
    check_imports(&optional_header32(), 4, ORDINAL_FLAG32)
}

#[test]
fn reads_imports_of_64_bit_image() -> Result<(), VmiError> {
    check_imports(&optional_header64(), 8, ORDINAL_FLAG64)
}

#[test]
fn ends_walk_at_descriptor_without_name_or_first_thunk() -> Result<(), VmiError> {
    // The first descriptor loses its `Name` or its `FirstThunk`, and a whole
    // descriptor follows it.
    for offset in [0x0c, 0x10] {
        let mut directory = import_directory(8, ORDINAL_FLAG64);
        put(&mut directory, offset, &0_u32.to_le_bytes());

        let image = import_image(&optional_header64(), &directory);
        let file = PeFile::new(&image).map_err(WindowsError::from)?;
        let imports = file.import_directory()?.expect("import directory");

        assert!(
            imports
                .descriptors()
                .map_err(WindowsError::from)?
                .is_empty()
        );
    }

    Ok(())
}

#[test]
fn gives_no_import_without_import_name_table() -> Result<(), VmiError> {
    // The first descriptor has no import name table, and the second points
    // to one past `SizeOfImage`. Both keep their names.
    let mut directory = import_directory(8, ORDINAL_FLAG64);
    put(&mut directory, 0x00, &0_u32.to_le_bytes());
    put(&mut directory, 0x14, &SIZE_OF_IMAGE.to_le_bytes());

    let image = import_image(&optional_header64(), &directory);
    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let imports = file.import_directory()?.expect("import directory");
    let descriptors = imports.descriptors().map_err(WindowsError::from)?;

    assert_eq!(descriptors.len(), 2);
    assert!(matches!(imports.import(&descriptors[0], 0), Ok(None)));
    assert!(matches!(imports.import(&descriptors[1], 0), Ok(None)));

    Ok(())
}

#[test]
fn fails_for_name_before_descriptors() -> Result<(), VmiError> {
    // The DLL's name and the first import's hint and name lie at
    // `NAMES_RVA`, in the section but before the descriptors.
    let mut directory = import_directory(8, ORDINAL_FLAG64);
    put(&mut directory, 0x0c, &NAMES_RVA.to_le_bytes());
    put(&mut directory, 0x40, &thunk(8, (NAMES_RVA + 0x10).into()));

    let mut image = image(
        &optional_header64(),
        &[section(
            NAMES_RVA,
            DIRECTORY_RVA - NAMES_RVA + directory.len() as u32,
        )],
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        directory.len() as u32,
        &directory,
    );
    put(&mut image, NAMES_RVA as usize, b"KERNEL32.dll\0");
    put(
        &mut image,
        NAMES_RVA as usize + 0x10,
        &0x00d6_u16.to_le_bytes(),
    );
    put(&mut image, NAMES_RVA as usize + 0x12, b"CreateFileW\0");

    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let imports = file.import_directory()?.expect("import directory");
    let descriptors = imports.descriptors().map_err(WindowsError::from)?;

    assert!(matches!(
        imports.name(&descriptors[0]),
        Err(PeError::InvalidImportTable)
    ));
    assert!(matches!(
        imports.import(&descriptors[0], 0),
        Err(PeError::InvalidImportTable)
    ));
    assert!(matches!(
        imports.import(&descriptors[0], 1),
        Ok(Some(Import::Ordinal(7)))
    ));

    Ok(())
}

#[test]
fn reads_delay_load_imports_before_descriptors() -> Result<(), VmiError> {
    // Two descriptors, the second without `IMAGE_DELAYLOAD_RVA_BASED`, and
    // the descriptor of zeros that ends the array. Both descriptors point to
    // the DLL's name and to the import name table before them.
    let mut directory = vec![0; 0x60];
    put(
        &mut directory,
        0x00,
        &IMAGE_DELAYLOAD_RVA_BASED.to_le_bytes(),
    );
    put(&mut directory, 0x04, &NAMES_RVA.to_le_bytes());
    put(&mut directory, 0x10, &(NAMES_RVA + 0x20).to_le_bytes());
    put(&mut directory, 0x24, &NAMES_RVA.to_le_bytes());
    put(&mut directory, 0x30, &(NAMES_RVA + 0x20).to_le_bytes());

    let mut image = image(
        &optional_header64(),
        &[section(
            NAMES_RVA,
            DIRECTORY_RVA - NAMES_RVA + directory.len() as u32,
        )],
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
        directory.len() as u32,
        &directory,
    );

    // The DLL's name, the import name table, and the hint with the name of
    // the import by name.
    put(&mut image, NAMES_RVA as usize, b"d3d9.dll\0");
    put(
        &mut image,
        NAMES_RVA as usize + 0x20,
        &thunk(8, (NAMES_RVA + 0x40).into()),
    );
    put(
        &mut image,
        NAMES_RVA as usize + 0x28,
        &thunk(8, ORDINAL_FLAG64 | 3),
    );
    put(
        &mut image,
        NAMES_RVA as usize + 0x40,
        &0x0010_u16.to_le_bytes(),
    );
    put(&mut image, NAMES_RVA as usize + 0x42, b"Direct3DCreate9\0");

    let file = PeFile::new(&image).map_err(WindowsError::from)?;
    let imports = file
        .delay_import_directory()?
        .expect("delay-load import directory");
    let descriptors = imports.descriptors().map_err(WindowsError::from)?;

    assert_eq!(descriptors.len(), 2);
    assert_eq!(
        imports.name(&descriptors[0]).map_err(WindowsError::from)?,
        &b"d3d9.dll"[..]
    );
    assert!(matches!(
        imports.import(&descriptors[0], 0),
        Ok(Some(Import::Name(0x0010, b"Direct3DCreate9")))
    ));
    assert!(matches!(
        imports.import(&descriptors[0], 1),
        Ok(Some(Import::Ordinal(3)))
    ));
    assert!(matches!(imports.import(&descriptors[0], 2), Ok(None)));
    assert!(matches!(
        imports.name(&descriptors[1]),
        Err(PeError::InvalidDelayImportTable)
    ));
    assert!(matches!(
        imports.import(&descriptors[1], 0),
        Err(PeError::InvalidDelayImportTable)
    ));

    Ok(())
}
