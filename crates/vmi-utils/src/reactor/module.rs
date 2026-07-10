//! Module enum and metadata types emitted by [`define_modules!`].
//!
//! [`define_modules!`]: super::define_modules!

use std::fmt::Debug;

use vmi_core::{Va, VmiError, VmiOs, os::ProcessObject};

use super::ProfileRef;

/// Module set monitored by a reactor.
///
/// Implemented by the enum that [`define_modules!`] produces. The enum
/// variants name guest modules to resolve. Slot 0 is reserved for the
/// kernel image.
///
/// [`define_modules!`]: super::define_modules!
pub trait ReactorModule<Os>: Debug + Copy + 'static
where
    Os: VmiOs + 'static,
{
    /// Per-variant module metadata.
    const METADATA: &'static [ModuleMetadata<Self, Os>];

    /// Slot reserved for the kernel image.
    const KERNEL_SLOT: usize;

    /// Returns the slot index occupied by this variant.
    fn slot(self) -> usize;
}

/// Privilege level at which a module is loaded.
pub enum ModuleMode {
    /// Loaded in the kernel address space.
    Kernel,

    /// Loaded in a user-mode process address space.
    User,
}

/// Process filter for user-mode modules.
pub enum ModuleProcessFilter<Os>
where
    Os: VmiOs + 'static,
{
    /// Match by exact image name, case-insensitive.
    Name(&'static str),

    /// Match by user-supplied predicate over the process.
    Predicate(&'static dyn for<'a, 'b> Fn(&'a Os::Process<'b>) -> Result<bool, VmiError>),
}

/// Compile-time descriptor that [`define_modules!`] emits for each variant of
/// the module enum.
///
/// [`define_modules!`]: super::define_modules
pub struct ModuleMetadata<Module, Os>
where
    Module: ReactorModule<Os>,
    Os: VmiOs + 'static,
{
    /// Image filename (e.g. `"ntdll.dll"`), or `"kernel"` for the kernel slot.
    pub name: &'static str,

    /// Process filter selecting which process maps this module,
    /// or `None` for any process.
    pub process: Option<ModuleProcessFilter<Os>>,

    /// Variant tag, or `None` for the kernel slot.
    pub module: Option<Module>,

    /// Privilege level at which the module is loaded.
    pub mode: ModuleMode,

    /// Whether the module is allowed to be absent from the guest.
    pub optional: bool,
}

/// Successfully resolved entry for a module variant.
pub struct ResolvedModule<'a> {
    /// Process whose page tables map this module's image.
    ///
    /// `None` for kernel modules, which share the global kernel mapping.
    pub process: Option<ProcessObject>,

    /// Base address at which the module is loaded in the guest.
    pub base_address: Va,

    /// Symbol profile for the module.
    pub profile: ProfileRef<'a>,
}
