mod kernel_module;
mod user_module;

use isr_cache::{CodeView, IsrCache};
use vmi_core::{VmiError, VmiState, driver::VmiRead};
use vmi_os_windows::{WindowsOs, WindowsProcess};

use super::{super::ArchAdapter, OsAdapter, Resolved};

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
{
    type DebugSignature = CodeView;

    // Note: we use `name = "resolver"` for both `resolve_kernel_module` and
    //       `resolve_user_module`.
    //
    // The inner spans in `kernel_module::resolve` and `user_module::resolve`
    // are named "kernel" and "user" respectively, so we can still distinguish
    // them when needed.

    #[tracing::instrument(name = "resolver", skip_all)]
    fn resolve_kernel_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &WindowsProcess<Driver>,
    ) -> Result<Option<Resolved<Self>>, VmiError> {
        kernel_module::resolve(vmi, isr, name, process)
    }

    #[tracing::instrument(name = "resolver", skip_all)]
    fn resolve_user_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &WindowsProcess<Driver>,
    ) -> Result<Option<Resolved<Self>>, VmiError> {
        user_module::resolve(vmi, isr, name, process)
    }
}
