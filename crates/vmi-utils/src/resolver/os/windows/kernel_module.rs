use isr_cache::IsrCache;
use vmi_core::{VmiError, VmiState, driver::VmiRead, os::VmiOsModule as _};
use vmi_os_windows::{PeImageExt as _, WindowsOs};

use super::super::{super::ArchAdapter, Resolved};

/// Locates the kernel module matching `name` and extracts its
/// codeview from the live in-memory image.
#[tracing::instrument(name = "kernel", skip_all)]
pub fn resolve<Driver>(
    vmi: &VmiState<WindowsOs<Driver>>,
    _isr: &IsrCache,
    name: &str,
) -> Result<Option<Resolved<WindowsOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    let module = match vmi.os().find_module(name)? {
        Some(module) => module,
        None => return Ok(None),
    };

    let image_base = module.base_address()?;
    let codeview = match vmi.os().image(image_base)?.codeview()? {
        Some(codeview) => codeview,
        None => return Ok(None),
    };

    Ok(Some(Resolved {
        process: None,
        image_base,
        debug_signature: codeview,
    }))
}
