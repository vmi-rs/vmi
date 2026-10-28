//! Tests of the export and load configuration directories on PE images built
//! in a buffer.

use vmi_core::{Va, VmiError};
use zerocopy::{FromZeros as _, IntoBytes as _};

use super::{
    ExportTarget, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory, ImageDosHeader,
    ImageFileHeader, ImageOptionalHeader32, ImageOptionalHeader64, PeFile, PeImage as _,
};
use crate::WindowsError;

/// The RVA of the directory in the built images.
const DIRECTORY_RVA: u32 = 0x200;

/// Returns a PE image without sections, with `optional_header` and the
/// directory of the data directory entry `index` at `DIRECTORY_RVA`.
///
/// The data directory entry gives the size `entry_size`, and `directory`
/// holds the directory's bytes. In an image without sections, an RVA is
/// also the offset in the file.
fn image(optional_header: &[u8], index: usize, entry_size: u32, directory: &[u8]) -> Vec<u8> {
    let mut dos_header = ImageDosHeader::new_zeroed();
    dos_header.e_magic = IMAGE_DOS_SIGNATURE;
    dos_header.e_lfanew = size_of::<ImageDosHeader>() as u32;

    let mut data_directories = [ImageDataDirectory::new_zeroed(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    data_directories[index] = ImageDataDirectory {
        virtual_address: DIRECTORY_RVA,
        size: entry_size,
    };

    let mut file_header = ImageFileHeader::new_zeroed();
    file_header.size_of_optional_header =
        (optional_header.len() + data_directories.as_bytes().len()) as u16;

    let mut image = Vec::new();
    image.extend_from_slice(dos_header.as_bytes());
    image.extend_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
    image.extend_from_slice(file_header.as_bytes());
    image.extend_from_slice(optional_header);
    image.extend_from_slice(data_directories.as_bytes());
    image.resize(DIRECTORY_RVA as usize, 0);
    image.extend_from_slice(directory);
    image
}

/// Returns the bytes of a PE32 optional header with every data directory
/// entry.
fn optional_header32() -> Vec<u8> {
    let mut header = ImageOptionalHeader32::new_zeroed();
    header.magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    header.number_of_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32;
    header.as_bytes().to_vec()
}

/// Returns the bytes of a PE32+ optional header with every data directory
/// entry.
fn optional_header64() -> Vec<u8> {
    let mut header = ImageOptionalHeader64::new_zeroed();
    header.magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
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
