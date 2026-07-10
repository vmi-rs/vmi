use std::fs::File;

use isr_cache::{CodeView, ImageSignature, IsrCache};
use memmap2::Mmap;
use vmi_core::{
    Registers as _, VmiError, VmiState,
    driver::VmiRead,
    os::{VmiOsProcess as _, VmiOsProcessExt as _, VmiOsRegion as _, VmiOsUserModule as _},
};
use vmi_os_windows::{
    PeFile, PeImageExt as _, WindowsError, WindowsOs, WindowsProcess, WindowsUserModule,
};

use super::super::{super::ArchAdapter, Resolved};

/// Resolves a user module by name in `process` and tries to extract its
/// [`CodeView`].
#[tracing::instrument(
    name = "user",
    skip_all,
    fields(
        process = vmi_core::trace::process_name(process),
        module = name,
    )
)]
pub fn resolve<Driver>(
    vmi: &VmiState<WindowsOs<Driver>>,
    isr: &IsrCache,
    name: &str,
    process: &WindowsProcess<Driver>,
) -> Result<Option<Resolved<WindowsOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    match resolve_via_vad(vmi, process, name) {
        Ok(Some(response)) => {
            tracing::debug!(
                codeview = ?response.debug_signature,
                "module resolved via VAD"
            );
            return Ok(Some(response));
        }
        Ok(None) => return Ok(None),
        Err(VmiError::Translation(_)) => (),
        Err(err) => return Err(err),
    }

    tracing::debug!("failed to read module from VAD, trying PEB");

    match resolve_via_peb(isr, process, name) {
        Ok(Some(response)) => {
            tracing::debug!(
                codeview = ?response.debug_signature,
                "module resolved via PEB"
            );
            return Ok(Some(response));
        }
        Ok(None) => return Ok(None),
        Err(VmiError::Translation(_)) => (),
        Err(err) => return Err(err),
    }

    tracing::debug!(
        process = vmi_core::trace::process_name(process),
        "failed to read module from PEB, giving up on this process"
    );

    Ok(None)
}

/// Tries to resolve the module by reading the image from the VAD region.
#[tracing::instrument(name = "via_vad", skip_all)]
fn resolve_via_vad<Driver>(
    vmi: &VmiState<WindowsOs<Driver>>,
    process: &WindowsProcess<Driver>,
    name: &str,
) -> Result<Option<Resolved<WindowsOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    // return Err(VmiError::Translation(
    //     [vmi_core::AddressContext {
    //         va: vmi_core::Va(0),
    //         root: vmi_core::Pa(0),
    //     }]
    //     .into_iter()
    //     .collect(),
    // ));

    let region = match process.find_region(name)? {
        Some(region) => region,
        None => {
            tracing::debug!("VAD region not found");
            return Ok(None);
        }
    };

    tracing::debug!("region found, reading image");

    // Switch to the process's address space to read the image.

    let root = process.translation_root()?;
    let image_base = region.start()?;

    let mut registers = *vmi.registers();
    registers.set_translation_root(root.0, image_base);

    let vmi = vmi.with_registers(&registers);

    let codeview = match vmi.os().image(image_base)?.codeview()? {
        Some(codeview) => codeview,
        None => {
            tracing::debug!("codeview not found");
            return Ok(None);
        }
    };

    Ok(Some(Resolved {
        process: process.object()?,
        image_base,
        debug_signature: codeview,
    }))
}

/// Tries to resolve the module by walking the PEB loader list and downloading
/// the PE image from the symbol server.
#[tracing::instrument(name = "via_peb", skip_all)]
fn resolve_via_peb<Driver>(
    isr: &IsrCache,
    process: &WindowsProcess<Driver>,
    name: &str,
) -> Result<Option<Resolved<WindowsOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    let peb = match process.native_peb()? {
        Some(peb) => peb,
        None => {
            tracing::debug!("process has no PEB");
            return Ok(None);
        }
    };

    for entry in peb.ldr()?.in_load_order_modules()? {
        let entry = entry?;

        let image_signature = match image_signature_for(&entry, name)? {
            Some(image_signature) => image_signature,
            None => {
                // This is not the module we're looking for.
                continue;
            }
        };

        let image_base = entry.base_address().inspect_err(|err| {
            tracing::debug!(%err, "failed to read _LDR_DATA_TABLE_ENTRY.DllBase");
        })?;

        let codeview = match codeview_from_image_signature(isr, image_signature)? {
            Some(codeview) => codeview,
            None => {
                tracing::debug!("codeview not found");
                continue;
            }
        };

        return Ok(Some(Resolved {
            process: process.object()?,
            image_base,
            debug_signature: codeview,
        }));
    }

    Ok(None)
}

/// Builds the [`ImageSignature`] for [`WindowsUserModule`] **if** the name
/// matches the given module name.
fn image_signature_for<Driver>(
    entry: &WindowsUserModule<Driver>,
    desired_name: &str,
) -> Result<Option<ImageSignature>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    let name = entry.name().inspect_err(|err| {
        tracing::debug!(%err, "failed to read _LDR_DATA_TABLE_ENTRY.BaseDllName");
    })?;

    if !name.eq_ignore_ascii_case(desired_name) {
        return Ok(None);
    }

    let timestamp = entry.time_date_stamp().inspect_err(|err| {
        tracing::debug!(%err, "failed to read _LDR_DATA_TABLE_ENTRY.TimeDateStamp");
    })?;

    let size_of_image = entry.size().inspect_err(|err| {
        tracing::debug!(%err, "failed to read _LDR_DATA_TABLE_ENTRY.SizeOfImage");
    })? as u32;

    tracing::debug!("downloading image");
    Ok(Some(ImageSignature {
        name,
        timestamp,
        size_of_image,
    }))
}

/// Downloads the PE image identified by [`ImageSignature`] via [`IsrCache`]
/// and extracts its [`CodeView`].
fn codeview_from_image_signature(
    isr: &IsrCache,
    image_signature: ImageSignature,
) -> Result<Option<CodeView>, VmiError> {
    let image_path = isr.download_from_image_signature(image_signature)?;
    let mmap = File::open(&image_path).and_then(|file| {
        // SAFETY: The file is not modified while the Mmap is alive.
        unsafe { Mmap::map(&file) }
    })?;

    tracing::debug!("parsing PE file");
    PeFile::new(&mmap).map_err(WindowsError::from)?.codeview()
}
