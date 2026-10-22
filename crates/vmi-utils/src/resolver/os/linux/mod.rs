mod kernel_module;
mod user_module;

use isr_cache::IsrCache;
use vmi_core::{VmiError, VmiState, driver::VmiRead};
use vmi_os_linux::{ArchAdapter, BuildId, LinuxOs, LinuxProcess};

use super::{OsAdapter, Resolved};

impl<Driver> OsAdapter for LinuxOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type DebugSignature = BuildId;

    // Both `resolve_kernel_module` and `resolve_user_module` open a span named
    // "resolver". The inner spans in `kernel_module::resolve` and
    // `user_module::resolve` are named "kernel" and "user", which tell the two
    // apart.

    #[tracing::instrument(name = "resolver", skip_all)]
    fn resolve_kernel_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &LinuxProcess<Driver>,
    ) -> Result<Option<Resolved<Self>>, VmiError> {
        kernel_module::resolve(vmi, isr, name, process)
    }

    #[tracing::instrument(name = "resolver", skip_all)]
    fn resolve_user_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &LinuxProcess<Driver>,
    ) -> Result<Option<Resolved<Self>>, VmiError> {
        user_module::resolve(vmi, isr, name, process)
    }
}
