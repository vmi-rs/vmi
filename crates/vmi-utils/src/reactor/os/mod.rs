#[cfg(feature = "os-linux")]
mod linux;
#[cfg(feature = "os-windows")]
mod windows;

use isr_cache::{Entry, IsrCache};
use isr_core::Profile;
use vmi_core::{Architecture, PageFault, VmiContext, VmiError, VmiState};

use super::ModuleSymbols;
use crate::resolver::{self, Resolved};

/// Operating system-specific functionality used by the reactor.
pub trait OsAdapter: resolver::OsAdapter {
    /// Loads the symbols of a module that the resolver found.
    ///
    /// `entry` is the cache slot of the module. An adapter that loads an isr
    /// profile stores its entry there, and the returned symbols borrow it.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: the profile that isr finds for the `CodeView` record.
    /// - **Linux**: the module's kallsyms for a kernel module, and the
    ///   exports for the kernel and for a user library. The slot stays
    ///   empty.
    fn module_symbols<'a>(
        vmi: &VmiState<Self>,
        isr: &IsrCache,
        resolved: &Resolved<Self>,
        entry: &'a mut Option<Entry>,
    ) -> Result<ModuleSymbols<'a>, VmiError>;

    /// Returns the offset from the module base for a symbol value of a
    /// profile, or `None` when the value lies outside the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: the value itself, which a PDB profile stores as an
    ///   offset from the image base.
    /// - **Linux**: the distance from the profile's `_text`. The profile
    ///   stores each symbol's link address, and the kernel image base is
    ///   the runtime address of `_text`.
    fn profile_symbol_offset(profile: &Profile, value: u64) -> Option<u64>;

    /// Returns the interrupt that hands a handler's page fault to the guest,
    /// or `None` when the guest cannot take it.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: a page fault with error code 0.
    /// - **Linux**: a page fault for a user address while the vCPU runs in
    ///   user mode. The guest kernel treats a page fault in kernel mode as an
    ///   oops, and a user-mode access to a kernel address ends the process.
    fn page_fault(
        vmi: &VmiContext<Self>,
        fault: PageFault,
    ) -> Option<<Self::Architecture as Architecture>::Interrupt>;
}
