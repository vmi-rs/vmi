pub use isr_dl_pdb::CodeView; // re-export the CodeView struct from the isr-dl-pdb crate
use object::{
    endian::LittleEndian as LE,
    pe::{ImageDebugDirectory, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG},
    pod::slice_from_all_bytes,
    read::pe::ImageNtHeaders,
};
use vmi_core::{AddressContext, Architecture as _, VmiCore, VmiDriver, VmiError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::PeLite;

const CV_SIGNATURE_RSDS: u32 = 0x53445352; // 'RSDS'

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct CvInfoPdb70 {
    signature: u32,
    guid: [u8; 16],
    age: u32,
    // pdb_file_name: [u8; ???],
}

pub(crate) fn codeview_from_pe<Driver, Pe>(
    vmi: &VmiCore<Driver>,
    ctx: impl Into<AddressContext>,
    pe: &PeLite<Pe>,
) -> Result<Option<CodeView>, VmiError>
where
    Driver: VmiDriver,
    Pe: ImageNtHeaders,
{
    let ctx = ctx.into();

    //
    // Check for the debug directory.
    // Note that we arbitrarily limit the size of the debug directory
    // to 4kb.
    //

    let data_dir = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_DEBUG) {
        Some(data_dir) => data_dir,
        None => {
            tracing::warn!("No PE debug dir");
            return Ok(None);
        }
    };

    if data_dir.virtual_address.get(LE) == 0 {
        tracing::warn!("Invalid PE debug dir address");
        return Ok(None);
    }

    if data_dir.size.get(LE) == 0 {
        tracing::warn!("Invalid PE debug dir size");
        return Ok(None);
    }

    if data_dir.size.get(LE) > Driver::Architecture::PAGE_SIZE as u32 {
        tracing::warn!("PE debug dir size too large");
        return Ok(None);
    }

    //
    // Read the debug directory.
    //

    let data_dir_address = ctx.va + data_dir.virtual_address.get(LE) as u64;
    let data_dir_size = data_dir.size.get(LE) as usize;

    let mut debug_data = vec![0u8; data_dir_size];
    vmi.read((data_dir_address, ctx.root), &mut debug_data)?;

    let debug_dirs = match slice_from_all_bytes::<ImageDebugDirectory>(&debug_data) {
        Ok(debug_dirs) => debug_dirs,
        Err(_) => {
            tracing::warn!("Invalid PE debug dir size");
            return Ok(None);
        }
    };

    //
    // Find the CodeView debug info.
    //

    for debug_dir in debug_dirs {
        if debug_dir.typ.get(LE) != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }

        if debug_dir.address_of_raw_data.get(LE) == 0 {
            tracing::warn!("Invalid CodeView Info address");
            continue;
        }

        if debug_dir.size_of_data.get(LE) < size_of::<CvInfoPdb70>() as u32 {
            tracing::warn!("Invalid CodeView Info size");
            continue;
        }

        //
        // Read the CodeView debug info.
        //

        let info_address = ctx.va + debug_dir.address_of_raw_data.get(LE) as u64;
        let info_size = debug_dir.size_of_data.get(LE) as usize;

        let mut info_data = vec![0u8; info_size];
        vmi.read((info_address, ctx.root), &mut info_data)?;

        //
        // Parse the CodeView debug info.
        // Note that the path is located after the `CvInfoPdb70` struct.
        //

        let (info, pdb_path) = info_data.split_at(size_of::<CvInfoPdb70>());

        let info = match CvInfoPdb70::ref_from_bytes(info) {
            Ok(info) => info,
            Err(err) => {
                tracing::warn!(?err, "Invalid CodeView Info address");
                continue;
            }
        };

        if info.signature != CV_SIGNATURE_RSDS {
            tracing::warn!("Invalid CodeView signature");
            continue;
        }

        //
        // Parse the CodeView path.
        // Note that the path is supposed to be null-terminated,
        // so we need to trim it.
        //

        let path = String::from_utf8_lossy(pdb_path)
            .trim_end_matches('\0')
            .to_string();

        let guid0 = u32::from_le_bytes(info.guid[0..4].try_into().unwrap());
        let guid1 = u16::from_le_bytes(info.guid[4..6].try_into().unwrap());
        let guid2 = u16::from_le_bytes(info.guid[6..8].try_into().unwrap());
        let guid3 = &info.guid[8..16];

        let guid = format!(
            "{:08x}{:04x}{:04x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:01x}",
            guid0,
            guid1,
            guid2,
            guid3[0],
            guid3[1],
            guid3[2],
            guid3[3],
            guid3[4],
            guid3[5],
            guid3[6],
            guid3[7],
            info.age & 0xf,
        );

        return Ok(Some(CodeView { path, guid }));
    }

    Ok(None)
}
