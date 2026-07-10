//! Locates loaded modules in memory and extracts the information needed
//! to fetch their debug symbols.
//!
//! [`resolve_kernel_module`] and [`resolve_user_module`] return a
//! [`Resolved`] value containing the module's load address and an
//! OS-specific [`DebugSignature`]. The signature can then be passed
//! to an [`IsrCache`] to fetch the matching debug profile.
//!
//! [`DebugSignature`]: OsAdapter::DebugSignature

mod arch;
mod os;

use isr_cache::IsrCache;
use vmi_core::{
    Va, VmiError, VmiState,
    os::{ProcessObject, ProcessPredicate},
};

pub use self::{arch::ArchAdapter, os::OsAdapter};

/// A resolved module with the metadata needed to fetch its debug symbols.
pub struct Resolved<Os>
where
    Os: OsAdapter,
{
    /// Process in which the module was resolved.
    pub process: ProcessObject,

    /// Virtual address of the loaded module image.
    pub image_base: Va,

    /// The OS-specific identifier for the module's debug symbols.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: [`CodeView`]
    ///
    /// [`CodeView`]: isr_cache::CodeView
    pub debug_signature: Os::DebugSignature,
}

impl<Os> std::fmt::Debug for Resolved<Os>
where
    Os: OsAdapter,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("process", &self.process)
            .field("image_base", &self.image_base)
            .field("debug_signature", &self.debug_signature)
            .finish()
    }
}

impl<Os> Clone for Resolved<Os>
where
    Os: OsAdapter,
{
    fn clone(&self) -> Self {
        Self {
            process: self.process,
            image_base: self.image_base,
            debug_signature: self.debug_signature.clone(),
        }
    }
}

/// Resolves a kernel module by name in the first process matching
/// `process` predicate and extracts its [`DebugSignature`].
///
/// # Platform-specific
///
/// - **Windows**:
///   - Walks `PsLoadedModuleList` to find the matching
///     `_KLDR_DATA_TABLE_ENTRY`.
///   - Reads the [`CodeView`] directly from its `DllBase`.
///
/// # Notes
///
/// Use [`AnyProcess`] to resolve the module from any process that loads it.
///
/// The system process is usually the first in the enumeration, unless it
/// has been maliciously unlinked. To pin resolution to the system process,
/// use:
///
/// ```no_run
/// # use isr_cache::IsrCache;
/// # use vmi::{
/// #     VmiState,
/// #     arch::amd64::Amd64,
/// #     driver::VmiRead,
/// #     os::windows::WindowsOs,
/// #     utils::resolver::resolve_kernel_module_in,
/// # };
/// #
/// # fn example<Driver>(
/// #     vmi: &VmiState<WindowsOs<Driver>>,
/// #     isr: &IsrCache,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>,
/// # {
/// let system_process = vmi.os().system_process()?;
/// resolve_kernel_module_in(vmi, isr, "ntoskrnl.exe", &system_process)?;
/// # Ok(())
/// # }
/// ```
///
/// # Examples
///
/// ```no_run
/// # use isr_cache::IsrCache;
/// # use vmi::{
/// #     VmiState,
/// #     arch::amd64::Amd64,
/// #     driver::VmiRead,
/// #     os::{AnyProcess, windows::WindowsOs},
/// #     utils::resolver::resolve_kernel_module,
/// # };
/// #
/// # fn example<Driver>(
/// #     vmi: &VmiState<WindowsOs<Driver>>,
/// #     isr: &IsrCache,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>,
/// # {
/// resolve_kernel_module(vmi, isr, "ntoskrnl.exe", AnyProcess)?;
/// resolve_kernel_module(vmi, isr, "netio.sys", AnyProcess)?;
/// resolve_kernel_module(vmi, isr, "win32k.sys", "csrss.exe")?;
/// # Ok(())
/// # }
/// ```
///
/// [`DebugSignature`]: OsAdapter::DebugSignature
/// [`CodeView`]: isr_cache::CodeView
/// [`AnyProcess`]: vmi_core::os::AnyProcess
pub fn resolve_kernel_module<Os>(
    vmi: &VmiState<Os>,
    isr: &IsrCache,
    name: &str,
    process: impl ProcessPredicate<Os>,
) -> Result<Option<Resolved<Os>>, VmiError>
where
    Os: OsAdapter,
{
    for process in vmi.os().filter_processes(process)? {
        let process = process?;

        if let Some(resolved) = resolve_kernel_module_in(vmi, isr, name, &process)? {
            return Ok(Some(resolved));
        }
    }

    Ok(None)
}

/// Resolves a kernel module by name within `process`'s address space and
/// extracts its [`DebugSignature`].
///
/// This is the single-process form of [`resolve_kernel_module`], which
/// iterates the processes matching a predicate and delegates here.
///
/// [`DebugSignature`]: OsAdapter::DebugSignature
pub fn resolve_kernel_module_in<Os>(
    vmi: &VmiState<Os>,
    isr: &IsrCache,
    name: &str,
    process: &Os::Process<'_>,
) -> Result<Option<Resolved<Os>>, VmiError>
where
    Os: OsAdapter,
{
    Os::resolve_kernel_module(vmi, isr, name, process)
}

/// Resolves a user module by name in the first process matching
/// `process` predicate and extracts its [`DebugSignature`].
///
/// # Platform-specific
///
/// **Windows** tries two strategies in order:
///
/// - **VAD**:
///   - Locates the module's VAD region.
///   - Reads the [`CodeView`] from it.
///
/// - **PEB**:
///   - Walks `PEB.Ldr.InLoadOrderModuleList` to find the matching
///     `_LDR_DATA_TABLE_ENTRY`.
///   - Builds an "image signature" from its `TimeDateStamp` and `SizeOfImage`.
///   - Downloads the PE from the Microsoft symbol server via [`IsrCache`].
///   - Extracts the [`CodeView`] from it.
///
/// If both strategies fail (e.g. VAD and PEB are paged out), the module
/// is considered not found and `Ok(None)` is returned.
///
/// # Notes
///
/// Use [`AnyProcess`] to resolve the module from any process that loads it.
///
/// # Examples
///
/// ```no_run
/// # use isr_cache::IsrCache;
/// # use vmi::{
/// #     VmiState,
/// #     arch::amd64::Amd64,
/// #     driver::VmiRead,
/// #     os::{
/// #         AnyProcess, ProcessId, VmiOsProcess as _,
/// #         windows::{WindowsOs, WindowsProcess},
/// #     },
/// #     utils::resolver::resolve_user_module,
/// # };
/// #
/// # fn example<Driver>(
/// #     vmi: &VmiState<WindowsOs<Driver>>,
/// #     isr: &IsrCache,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>,
/// # {
/// resolve_user_module(vmi, isr, "ncrypt.dll", "lsass.exe")?;
/// resolve_user_module(vmi, isr, "ncrypt.dll", ProcessId(1234))?;
/// resolve_user_module(vmi, isr, "ncrypt.dll", AnyProcess)?;
/// resolve_user_module(vmi, isr, "ncrypt.dll", |process: &WindowsProcess<_>| {
///     // Match "lsass.exe" in SessionId 0.
///     Ok(
///         matches!(process.session()?, Some(session) if session.id()? == 0)
///             && process.name()?.eq_ignore_ascii_case("lsass.exe"),
///     )
/// })?;
/// # Ok(())
/// # }
/// ```
///
/// [`DebugSignature`]: OsAdapter::DebugSignature
/// [`CodeView`]: isr_cache::CodeView
/// [`AnyProcess`]: vmi_core::os::AnyProcess
pub fn resolve_user_module<Os>(
    vmi: &VmiState<Os>,
    isr: &IsrCache,
    name: &str,
    process: impl ProcessPredicate<Os>,
) -> Result<Option<Resolved<Os>>, VmiError>
where
    Os: OsAdapter,
{
    for process in vmi.os().filter_processes(process)? {
        let process = process?;

        if let Some(resolved) = resolve_user_module_in(vmi, isr, name, &process)? {
            return Ok(Some(resolved));
        }
    }

    Ok(None)
}

/// Resolves a user module by name within `process` and extracts its
/// [`DebugSignature`].
///
/// This is the single-process form of [`resolve_user_module`], which
/// iterates the processes matching a predicate and delegates here.
///
/// [`DebugSignature`]: OsAdapter::DebugSignature
pub fn resolve_user_module_in<Os>(
    vmi: &VmiState<Os>,
    isr: &IsrCache,
    name: &str,
    process: &Os::Process<'_>,
) -> Result<Option<Resolved<Os>>, VmiError>
where
    Os: OsAdapter,
{
    Os::resolve_user_module(vmi, isr, name, process)
}
