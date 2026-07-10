#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
mod windows;

use std::fmt::Debug;

use isr_cache::IsrCache;
use vmi_core::{VmiError, VmiOs, VmiState};

use super::Resolved;

/// Operating system-specific functionality used by the resolver.
pub trait OsAdapter: VmiOs {
    /// OS-specific identifier that locates its debug symbols.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: [`CodeView`].
    /// - **Linux**: GNU build-id from `.note.gnu.build-id`.
    ///
    /// [`CodeView`]: isr_cache::CodeView
    type DebugSignature: Debug + Clone;

    /// See [`resolve_kernel_module_in`].
    ///
    /// [`resolve_kernel_module_in`]: super::resolve_kernel_module_in
    fn resolve_kernel_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &Self::Process<'_>,
    ) -> Result<Option<Resolved<Self>>, VmiError>;

    /// See [`resolve_user_module_in`].
    ///
    /// [`resolve_user_module_in`]: super::resolve_user_module_in
    fn resolve_user_module(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        name: &str,
        process: &Self::Process<'_>,
    ) -> Result<Option<Resolved<Self>>, VmiError>;
}
