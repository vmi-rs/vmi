use isr_cache::IsrCache;
use vmi_core::{
    VmiError, VmiState,
    driver::VmiRead,
    os::{VmiOsProcess as _, VmiOsUserModule as _},
};
use vmi_os_linux::{ArchAdapter, LinuxError, LinuxOs, LinuxProcess, LinuxUserModule};

use super::super::Resolved;

/// How a user module matches the name that the resolver looks for.
#[derive(Debug, Clone, Copy)]
enum MatchBy {
    /// The name of the mapped file.
    FileName,

    /// The object's name from its dynamic section (`DT_SONAME`).
    Soname,
}

/// Resolves a user module by name in `process` and reads its GNU build-id.
///
/// The name must equal the file name of a module, such as `libc.so.6`, or
/// its `DT_SONAME`. The search compares the file names first, because a
/// file name lies in kernel memory and a `DT_SONAME` in user memory. The
/// build-id is read with the translation root of the process.
///
/// A page fault ends the search in this process with `Ok(None)`.
#[tracing::instrument(
    name = "user",
    skip_all,
    fields(
        process = vmi_core::trace::process_name(process),
        module = name,
    )
)]
pub fn resolve<Driver>(
    _vmi: &VmiState<LinuxOs<Driver>>,
    _isr: &IsrCache,
    name: &str,
    process: &LinuxProcess<Driver>,
) -> Result<Option<Resolved<LinuxOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    for match_by in [MatchBy::FileName, MatchBy::Soname] {
        match resolve_by(process, name, match_by) {
            Ok(Some(resolved)) => {
                tracing::debug!(
                    ?match_by,
                    build_id = %resolved.debug_signature,
                    "module resolved"
                );
                return Ok(Some(resolved));
            }
            Ok(None) => (),
            Err(VmiError::PageFault(pf)) => {
                tracing::debug!(va = %pf.va, "page fault, giving up on this process");
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
    }

    tracing::debug!("module not found");
    Ok(None)
}

/// Searches the user modules of `process` for one that matches `name` in
/// the way that `match_by` picks, and reads its build-id.
///
/// A module whose mapping is not an ELF image fails the build-id read, and
/// the search skips it. A module without a build-id ends the search with
/// `Ok(None)`.
fn resolve_by<Driver>(
    process: &LinuxProcess<Driver>,
    name: &str,
    match_by: MatchBy,
) -> Result<Option<Resolved<LinuxOs<Driver>>>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    for module in process.user_modules()? {
        let module = module?;

        if !name_matches(&module, name, match_by)? {
            continue;
        }

        let image_base = module.base_address()?;

        let build_id = match module.build_id() {
            Ok(Some(build_id)) => build_id,
            Ok(None) => {
                tracing::debug!(base = %image_base, "build-id not found");
                return Ok(None);
            }
            Err(err) if is_corrupted_image(&err) => {
                tracing::debug!(base = %image_base, %err, "module is not an ELF image, skipping");
                continue;
            }
            Err(err) => return Err(err),
        };

        return Ok(Some(Resolved {
            process: process.object()?,
            image_base,
            debug_signature: build_id,
        }));
    }

    Ok(None)
}

/// Checks if a user module matches `name` in the way that `match_by` picks.
fn name_matches<Driver>(
    module: &LinuxUserModule<Driver>,
    name: &str,
    match_by: MatchBy,
) -> Result<bool, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    match match_by {
        MatchBy::FileName => Ok(module.name()? == name),
        MatchBy::Soname => Ok(module.soname()?.is_some_and(|soname| soname == name)),
    }
}

/// Checks if an error says that an image in guest memory is not a valid ELF
/// image.
fn is_corrupted_image(err: &VmiError) -> bool {
    match err {
        VmiError::Os(err) => matches!(
            err.downcast_ref::<LinuxError>(),
            Some(LinuxError::CorruptedImage(_))
        ),
        _ => false,
    }
}
