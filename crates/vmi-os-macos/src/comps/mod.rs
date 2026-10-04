mod file;
mod image;
mod mapped;
mod module;
mod process;
mod region;
mod thread;
mod user_module;
mod vnode;

use vmi_core::{Va, VmiError, VmiState, driver::VmiRead};

pub use self::{
    file::{MacOsFileKind, MacOsOpenFile},
    image::MacOsImage,
    mapped::MacOsMapped,
    module::MacOsModule,
    process::{MacOsProcess, MacOsProcessArguments},
    region::MacOsRegion,
    thread::MacOsThread,
    user_module::MacOsUserModule,
    vnode::MacOsVnode,
};
use crate::{ArchAdapter, MacOs, macho::fixed_string};

/// Reads a fixed-size, NUL-padded character array from kernel memory.
pub(crate) fn read_fixed_string<Driver>(
    vmi: VmiState<MacOs<Driver>>,
    va: Va,
    size: u64,
) -> Result<String, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    let mut buffer = vec![0u8; size as usize];
    vmi.read(va, &mut buffer)?;
    Ok(fixed_string(&buffer))
}
