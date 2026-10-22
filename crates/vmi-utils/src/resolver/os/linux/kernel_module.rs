use isr_cache::IsrCache;
use vmi_core::{
    VmiError, VmiState,
    driver::VmiRead,
    os::{VmiOsModule as _, VmiOsProcess as _},
};
use vmi_os_linux::{ArchAdapter, LinuxModule, LinuxOs, LinuxProcess};

use super::super::Resolved;

/// The name that the resolver gives the kernel image, as `inject!` does.
const KERNEL_IMAGE_NAME: &str = "kernel";

/// Locates the kernel image or the kernel module matching `name` and reads
/// its GNU build-id.
///
/// `kernel` names the kernel image. Any other name must equal the name of a
/// loaded module, such as `sch_fq_codel`. Kernel memory is the same in
/// every process, and `process` only fills [`Resolved::process`].
#[tracing::instrument(
    name = "kernel",
    skip_all,
    fields(
        process = vmi_core::trace::process_name(process),
        module = name,
    )
)]
pub fn resolve<Driver>(
    vmi: &VmiState<LinuxOs<Driver>>,
    _isr: &IsrCache,
    name: &str,
    process: &LinuxProcess<Driver>,
) -> Result<Option<Resolved<LinuxOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    let image_base = if name == KERNEL_IMAGE_NAME {
        vmi.os().kernel_image_base()?
    }
    else {
        let module = vmi
            .os()
            .find_module(|module: &LinuxModule<Driver>| Ok(module.name()? == name))?;

        match module {
            Some(module) => module.base_address()?,
            None => {
                tracing::debug!("module not found");
                return Ok(None);
            }
        }
    };

    let build_id = match vmi.os().image(image_base)?.build_id()? {
        Some(build_id) => build_id,
        None => {
            tracing::debug!("build-id not found");
            return Ok(None);
        }
    };

    tracing::debug!(%build_id, "module resolved");

    Ok(Some(Resolved {
        process: process.object()?,
        image_base,
        debug_signature: build_id,
    }))
}
