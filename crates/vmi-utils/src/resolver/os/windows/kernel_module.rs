use isr_cache::IsrCache;
use vmi_core::{
    Registers, VmiError, VmiState,
    driver::VmiRead,
    os::{VmiOsModule as _, VmiOsProcess as _},
};
use vmi_os_windows::{PeImageExt as _, WindowsOs, WindowsProcess};

use super::super::{super::ArchAdapter, Resolved};

/// Locates the kernel module matching `name` and extracts its codeview
/// from the live in-memory image in `process`'s address space.
#[tracing::instrument(
    name = "kernel",
    skip_all,
    fields(process = vmi_core::trace::process_name(process))
)]
pub fn resolve<Driver>(
    vmi: &VmiState<WindowsOs<Driver>>,
    _isr: &IsrCache,
    name: &str,
    process: &WindowsProcess<Driver>,
) -> Result<Option<Resolved<WindowsOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    let module = match vmi.os().find_module(name)? {
        Some(module) => module,
        None => return Ok(None),
    };

    let root = process.translation_root()?;
    let image_base = module.base_address()?;

    let mut registers = *vmi.registers();
    registers.set_translation_root(root.0, image_base);

    let vmi = vmi.with_registers(&registers);

    let codeview = match vmi.os().image(image_base)?.codeview()? {
        Some(codeview) => codeview,
        None => return Ok(None),
    };

    Ok(Some(Resolved {
        process: process.object()?,
        image_base,
        debug_signature: codeview,
    }))
}
