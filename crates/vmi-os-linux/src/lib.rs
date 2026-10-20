//! # Linux OS-specific VMI operations
//!
//! This crate provides functionality for introspecting Linux-based virtual
//! machines, working in conjunction with the `vmi-core` crate. It reads the
//! symbols and structure offsets of the guest's kernel from an isr profile.
//!
//! ## Supported kernels
//!
//! Linux 6.8 and later on AMD64. The kernel changed where it keeps the pointer
//! to the current task in 6.15, and the crate picks the layout from the symbols
//! in the profile, not from the version string.
//!
//! Under page table isolation (KPTI), a vCPU in user mode runs on page tables
//! that map almost none of the kernel. The crate then reads the kernel through
//! the kernel page tables of the same process. Its methods therefore work with
//! any vCPU's registers.
//!
//! ## Features
//!
//! - Kernel discovery: the banner, the KASLR offset, the kernel image base and
//!   KPTI
//! - Processes and threads, including the current process and thread
//! - Memory regions of a process, with the paths of mapped files
//! - Kernel modules
//! - Syscall and function arguments and the return value
//!
//! Images, user-mode modules and the last error are not supported yet. Their
//! methods return `VmiError::NotSupported`.
//!
//! The example `linux-process-list` of the `vmi` crate lists the processes,
//! threads, memory regions and kernel modules of a guest.
//!
//! ## Safety Considerations
//!
//! Many operations in this crate require pausing the VM to ensure consistency.
//! Always pause the VM when performing operations that could be affected by
//! concurrent changes in the guest OS. Make sure that the profile matches the
//! guest's kernel, as structure layouts change between kernel builds. Handle
//! errors appropriately, as VMI operations can fail for many reasons, such as
//! invalid memory access or a profile of another kernel.
//!
//! ## Examples
//!
//! ```no_run
//! # use vmi::{
//! #     VmiCore,
//! #     arch::amd64::Amd64,
//! #     driver::VmiVmControl,
//! #     os::linux::LinuxOs,
//! # };
//! #
//! # fn example<Driver>(
//! #     vmi: &VmiCore<Driver>,
//! #     _os: &LinuxOs<Driver>
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     Driver: VmiVmControl<Architecture = Amd64>,
//! # {
//! let _guard = vmi.pause_guard()?;
//! // Perform introspection operations here
//! // VM automatically resumes when `_guard` goes out of scope
//! # Ok(())
//! # }
//! ```
//!
//! Always consider the potential for race conditions and ensure you're
//! working with a consistent state of the guest OS.

// Allow the naming conventions of the Linux kernel, such as `entry_SYSCALL_64`.
#![allow(non_snake_case)]

use isr_core::Profile;
use once_cell::unsync::OnceCell;
use vmi_core::{
    Architecture, Pa, Va, VmiCore, VmiDriver, VmiError, VmiState,
    driver::VmiRead,
    os::{ProcessObject, ThreadObject, VmiOs},
};
use vmi_macros::derive_trait_from_impl;

mod arch;
pub use self::arch::ArchAdapter;

mod comps;
pub use self::comps::{
    LinuxDentry, LinuxFile, LinuxImage, LinuxMmStruct, LinuxModule, LinuxMount, LinuxPath,
    LinuxProcess, LinuxRegion, LinuxThread, LinuxUserModule, LinuxVfsMount,
};

mod error;
pub use self::error::LinuxError;

mod iter;
pub use self::iter::{ListEntryIterator, MapleTreeIterator};

mod offsets;
pub use self::offsets::{Offsets, Symbols};

/// VMI operations for the Linux operating system.
///
/// `LinuxOs` provides methods and utilities for introspecting a Linux-based
/// virtual machine. It encapsulates Linux-specific knowledge and operations,
/// allowing for high-level interactions with the guest OS structures and
/// processes.
///
/// # Usage
///
/// Create an instance of [`LinuxOs`] using a [`Profile`] of the guest's
/// kernel. The kernel banner, which [`find_kernel`] reads from memory, names
/// the kernel build and lets isr find its debug symbols:
///
/// ```no_run
/// use isr::cache::IsrCache;
/// use vmi::{
///     VcpuId, VmiCore,
///     arch::amd64::Amd64,
///     driver::{VmiQueryRegisters, VmiRead, VmiVmControl},
///     os::linux::LinuxOs,
/// };
///
/// # fn example<Driver>(
/// #     driver: Driver
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>
/// #           + VmiQueryRegisters<Architecture = Amd64>
/// #           + VmiVmControl<Architecture = Amd64>,
/// # {
/// // Setup VMI.
/// let core = VmiCore::new(driver)?;
///
/// // Find the kernel banner.
/// // This is necessary in order to load the profile.
/// let kernel_info = {
///     let _guard = core.pause_guard()?;
///     let registers = core.registers(VcpuId(0))?;
///
///     LinuxOs::find_kernel(&core, &registers)?.expect("kernel information")
/// };
///
/// // Load the profile using the ISR library.
/// let isr = IsrCache::new("cache")?;
/// let entry = isr.entry_from_linux_banner(&kernel_info.banner)?;
/// let profile = entry.profile()?;
///
/// // Create a new `LinuxOs` instance.
/// let os = LinuxOs::<Driver>::new(&profile)?;
/// # Ok(())
/// # }
/// ```
///
/// # Important Notes
///
/// - Many methods of this struct require pausing the VM to ensure consistency.
///   Use [`pause_guard`] when performing operations that might be affected
///   by concurrent changes in the guest OS.
///
/// - Kernel memory is read through the page tables of the vCPU of each
///   [`VmiState`]. With KPTI, the page tables of user mode map little of the
///   kernel, so most reads fail while that vCPU runs in user mode.
///
/// # Examples
///
/// Retrieving information about the current process:
///
/// ```no_run
/// # use vmi::{
/// #     VmiState,
/// #     arch::amd64::Amd64,
/// #     driver::VmiRead,
/// #     os::{VmiOsProcess as _, linux::LinuxOs},
/// # };
/// #
/// # fn example<Driver>(
/// #     vmi: &VmiState<LinuxOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>,
/// # {
/// let process = vmi.os().current_process()?;
/// let process_id = process.id()?;
/// let process_name = process.name()?;
/// println!("Current process: {} (PID: {})", process_name, process_id);
/// # Ok(())
/// # }
/// ```
///
/// Enumerating all processes:
///
/// ```no_run
/// # use vmi::{
/// #     VmiState,
/// #     arch::amd64::Amd64,
/// #     driver::VmiRead,
/// #     os::{VmiOsProcess as _, linux::LinuxOs},
/// # };
/// #
/// # fn example<Driver>(
/// #     vmi: &VmiState<LinuxOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Amd64>,
/// # {
/// for process in vmi.os().processes()? {
///     let process = process?;
///     println!("Process: {} (PID: {})", process.name()?, process.id()?);
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`find_kernel`]: Self::find_kernel
/// [`pause_guard`]: VmiCore::pause_guard
pub struct LinuxOs<Driver>
where
    Driver: VmiDriver,
{
    /// Structure offsets from the profile.
    offsets: Offsets,

    /// Kernel symbols from the profile.
    symbols: Symbols,

    /// Location of the per-CPU pointer to the current task.
    current_task: CurrentTask,

    /// Runtime address of a kernel symbol minus its link-time address.
    kaslr_offset: OnceCell<u64>,

    /// The kernel banner.
    kernel_information_string: OnceCell<String>,

    /// Whether the kernel runs with page table isolation.
    kpti_enabled: OnceCell<bool>,

    _marker: std::marker::PhantomData<Driver>,
}

/// Information about the Linux kernel, found before a profile exists.
#[derive(Debug)]
pub struct LinuxKernelInformation {
    /// The kernel banner, the content of `linux_banner` without the final
    /// newline.
    ///
    /// Ubuntu kernels end it with their version signature, such as
    /// "(Ubuntu 7.0.0-38.38-generic 7.0.14)", which isr needs to find the
    /// debug symbols.
    pub banner: String,
}

/// Location of the per-CPU pointer to the current task.
///
/// The address of the pointer for one CPU is the per-CPU base of that CPU
/// plus the value that this type describes.
#[derive(Debug, Clone, Copy)]
enum CurrentTask {
    /// The per-CPU variable `current_task` of Linux 6.15 and later.
    ///
    /// The value is the link-time address of the symbol. Since 6.15, per-CPU
    /// symbols are regular kernel addresses that move with KASLR.
    Relocated(u64),

    /// The field `pcpu_hot.current_task` of Linux 6.2 to 6.14.
    ///
    /// The value is the zero-based per-CPU offset of the field. Such offsets
    /// do not move with KASLR.
    ZeroBased(u64),
}

impl CurrentTask {
    /// Picks the layout from the symbols in the profile.
    ///
    /// A relocated `current_task` lies in the kernel image, at or above
    /// `__START_KERNEL_map`. A zero-based `pcpu_hot` lies below it.
    fn new(offsets: &Offsets, symbols: &Symbols) -> Result<Self, LinuxError> {
        /// Start of the kernel image mapping on x86-64.
        const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_0000;

        if let Some(current_task) = symbols.current_task
            && current_task >= START_KERNEL_MAP
        {
            return Ok(Self::Relocated(current_task));
        }

        if let Some(pcpu_hot) = symbols.pcpu_hot
            && let Some(PCPU_HOT) = &offsets.pcpu_hot
            && pcpu_hot < START_KERNEL_MAP
        {
            return Ok(Self::ZeroBased(pcpu_hot + PCPU_HOT.current_task.offset()));
        }

        Err(LinuxError::UnsupportedProfile(
            "no per-CPU current_task (Linux 6.15 and later) or pcpu_hot (Linux 6.2 to 6.14)",
        ))
    }
}

macro_rules! offset {
    ($vmi:expr, $field:ident) => {
        &$vmi.underlying_os().offsets.$field
    };
}

pub(crate) use offset;

macro_rules! symbol {
    ($vmi:expr, $field:ident) => {
        $vmi.underlying_os().symbols.$field
    };
}

pub(crate) use symbol;

macro_rules! this {
    ($vmi:expr) => {
        $vmi.underlying_os()
    };
}

#[derive_trait_from_impl(LinuxOsExt)]
impl<Driver> LinuxOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new `LinuxOs` instance.
    pub fn new(profile: &Profile) -> Result<Self, VmiError> {
        Self::create(profile, None)
    }

    /// Creates a new `LinuxOs` instance with a known kernel image base
    /// address.
    ///
    /// The base address is the runtime address of `_text`, which fixes the
    /// KASLR offset without reading `MSR_LSTAR`.
    pub fn with_kernel_base(profile: &Profile, kernel_base: Va) -> Result<Self, VmiError> {
        Self::create(profile, Some(kernel_base))
    }

    /// Creates the instance and picks the layout of the per-CPU current
    /// task.
    fn create(profile: &Profile, kernel_base: Option<Va>) -> Result<Self, VmiError> {
        let offsets = Offsets::new(profile)?;
        let symbols = Symbols::new(profile)?;
        let current_task = CurrentTask::new(&offsets, &symbols)?;

        let kaslr_offset = match kernel_base {
            Some(kernel_base) => OnceCell::with_value(kernel_base.0.wrapping_sub(symbols._text)),
            None => OnceCell::new(),
        };

        Ok(Self {
            offsets,
            symbols,
            current_task,
            kaslr_offset,
            kernel_information_string: OnceCell::new(),
            kpti_enabled: OnceCell::new(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns a reference to the Linux-specific structure offsets.
    pub fn offsets(vmi: VmiState<'_, Self>) -> &Offsets {
        &this!(vmi).offsets
    }

    /// Returns a reference to the Linux-specific symbols.
    pub fn symbols(vmi: VmiState<'_, Self>) -> &Symbols {
        &this!(vmi).symbols
    }

    /// Locates the Linux kernel banner in memory based on the CPU registers.
    /// This function is architecture-specific.
    ///
    /// On AMD64, the banner is located by reading the virtual memory page by
    /// page forward from `MSR_LSTAR` until "Linux version " followed by a
    /// digit is found. Since Linux 6.1, the image holds a second, unused
    /// banner without the build time before the real one. The search
    /// therefore goes on for up to 16 MiB and returns the last banner of the
    /// same release.
    pub fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<LinuxKernelInformation>, VmiError> {
        Driver::Architecture::find_kernel(vmi, registers)
    }

    /// Returns the KASLR offset.
    ///
    /// The offset is the runtime address of a kernel symbol minus its
    /// link-time address in the profile.
    ///
    /// # Notes
    ///
    /// The value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// On AMD64, the offset is `MSR_LSTAR` minus `entry_SYSCALL_64`.
    pub fn kaslr_offset(vmi: VmiState<Self>) -> Result<u64, VmiError> {
        Driver::Architecture::kaslr_offset(vmi)
    }

    /// Returns the runtime address of a kernel symbol.
    ///
    /// The symbol is a link-time address, such as a field of [`Symbols`].
    pub fn symbol_address(vmi: VmiState<Self>, symbol: u64) -> Result<Va, VmiError> {
        Ok(Va(symbol.wrapping_add(Self::kaslr_offset(vmi)?)))
    }

    /// Returns the per-CPU base of the vCPU of the VMI state.
    ///
    /// The address of a per-CPU variable for this CPU is the per-CPU base
    /// plus the runtime address of the variable (Linux 6.15 and later) or
    /// plus its zero-based offset (Linux 6.14 and earlier).
    pub fn per_cpu_base(vmi: VmiState<Self>) -> Va {
        Driver::Architecture::per_cpu_base(vmi)
    }

    /// Returns an iterator over a `list_head` list.
    ///
    /// For each entry, the iterator yields the entry address minus `offset`.
    /// With the offset of the `list_head` field in a structure, that is the
    /// structure that contains the entry.
    pub fn linked_list<'a>(
        vmi: VmiState<'a, Self>,
        list_head: Va,
        offset: u64,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + use<'a, Driver>, VmiError> {
        Ok(ListEntryIterator::new(vmi, list_head, offset))
    }

    /// Returns the address of the `task_struct` that runs on the vCPU of the
    /// VMI state.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the per-CPU `current_task` (Linux 6.15 and later) or
    /// `pcpu_hot.current_task` (Linux 6.14 and earlier).
    fn current_task(vmi: VmiState<Self>) -> Result<Va, VmiError> {
        let per_cpu_base = Self::per_cpu_base(vmi);
        if per_cpu_base.is_null() {
            return Err(LinuxError::CorruptedStruct("per-CPU base").into());
        }

        let pointer = match this!(vmi).current_task {
            CurrentTask::Relocated(current_task) => Self::symbol_address(vmi, current_task)?.0,
            CurrentTask::ZeroBased(current_task) => current_task,
        };

        let current_task = vmi.read_va_native(Va(per_cpu_base.0.wrapping_add(pointer)))?;
        if current_task.is_null() {
            return Err(LinuxError::CorruptedStruct("current_task").into());
        }

        Ok(current_task)
    }
}

impl<Driver> VmiOs for LinuxOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Architecture = Driver::Architecture;
    type Driver = Driver;

    type Process<'a> = LinuxProcess<'a, Driver>;
    type Thread<'a> = LinuxThread<'a, Driver>;
    type Image<'a> = LinuxImage<'a, Driver>;
    type Module<'a> = LinuxModule<'a, Driver>;
    type UserModule<'a> = LinuxUserModule<'a, Driver>;
    type Region<'a> = LinuxRegion<'a, Driver>;
    type Mapped<'a> = LinuxFile<'a, Driver>;

    /// Returns the kernel image base address.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the runtime address of `_text`.
    fn kernel_image_base(vmi: VmiState<Self>) -> Result<Va, VmiError> {
        Self::symbol_address(vmi, symbol!(vmi, _text))
    }

    /// Returns the kernel banner.
    ///
    /// # Notes
    ///
    /// The value is cached after the first read. The final newline is
    /// removed.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `linux_banner`.
    fn kernel_information_string(vmi: VmiState<Self>) -> Result<String, VmiError> {
        this!(vmi)
            .kernel_information_string
            .get_or_try_init(|| {
                let linux_banner = Self::symbol_address(vmi, symbol!(vmi, linux_banner))?;
                let banner = vmi.read_string(linux_banner)?;
                Ok(banner.trim_end_matches('\n').to_owned())
            })
            .cloned()
    }

    /// Checks if Kernel Page Table Isolation (KPTI) is enabled.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read. The read works with any
    /// vCPU state, also in user mode under KPTI.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the CPU feature `X86_FEATURE_PTI` in
    /// `boot_cpu_data.x86_capability`, bit 11 of word 7.
    fn kpti_enabled(vmi: VmiState<Self>) -> Result<bool, VmiError> {
        this!(vmi)
            .kpti_enabled
            .get_or_try_init(|| Driver::Architecture::kpti_enabled(vmi))
            .copied()
    }

    /// Returns the page table root that translates a virtual address.
    ///
    /// Under KPTI, a vCPU in user mode runs on the user page tables, which map
    /// almost none of the kernel. For a kernel address, the root then becomes
    /// the kernel page tables of the same process. Every kernel read thus
    /// works with any vCPU's registers.
    fn translation_root(vmi: VmiState<Self>, va: Va) -> Pa {
        Driver::Architecture::translation_root(vmi, va)
    }

    /// Returns an iterator over the loaded kernel modules.
    ///
    /// Modules that are still being loaded (`MODULE_STATE_UNFORMED`) are
    /// skipped, as the kernel skips them in `/proc/modules`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `modules` list, linked through `module.list`.
    fn modules<'a>(
        vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        let MODULE = offset!(vmi, module);

        let modules = Self::symbol_address(vmi, symbol!(vmi, modules))?;

        Ok(
            ListEntryIterator::new(vmi, modules, MODULE.list.offset()).filter_map(move |result| {
                let module = match result {
                    Ok(entry) => LinuxModule::new(vmi, entry),
                    Err(err) => return Some(Err(err)),
                };

                match module.is_unformed() {
                    Ok(true) => None,
                    Ok(false) => Some(Ok(module)),
                    Err(err) => Some(Err(err)),
                }
            }),
        )
    }

    /// Returns an iterator over the processes.
    ///
    /// The iterator yields the thread group leaders, kernel threads included,
    /// but not `init_task`, as `for_each_process` does.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the list `init_task.tasks`, linked through
    /// `task_struct.tasks`.
    fn processes<'a>(
        vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        let TASK_STRUCT = offset!(vmi, task_struct);

        let init_task = Self::symbol_address(vmi, symbol!(vmi, init_task))?;

        Ok(ListEntryIterator::new(
            vmi,
            init_task + TASK_STRUCT.tasks.offset(),
            TASK_STRUCT.tasks.offset(),
        )
        .map(move |result| result.map(|entry| LinuxProcess::new(vmi, ProcessObject(entry)))))
    }

    fn process(
        vmi: VmiState<'_, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        Ok(LinuxProcess::new(vmi, process))
    }

    /// Returns the current process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.group_leader` of the current task.
    fn current_process(vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        Self::current_thread(vmi)?.process()
    }

    /// Returns the system process.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `init_task`, the idle task of the boot CPU (PID 0).
    fn system_process(vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        let init_task = Self::symbol_address(vmi, symbol!(vmi, init_task))?;
        Ok(LinuxProcess::new(vmi, ProcessObject(init_task)))
    }

    fn thread(vmi: VmiState<'_, Self>, thread: ThreadObject) -> Result<Self::Thread<'_>, VmiError> {
        Ok(LinuxThread::new(vmi, thread))
    }

    /// Returns the current thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the per-CPU `current_task` (Linux 6.15 and later) or
    /// `pcpu_hot.current_task` (Linux 6.14 and earlier).
    fn current_thread(vmi: VmiState<'_, Self>) -> Result<Self::Thread<'_>, VmiError> {
        let current_task = Self::current_task(vmi)?;
        Ok(LinuxThread::new(vmi, ThreadObject(current_task)))
    }

    /// Not supported yet.
    fn image(_vmi: VmiState<'_, Self>, _image_base: Va) -> Result<Self::Image<'_>, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn module(vmi: VmiState<'_, Self>, module: Va) -> Result<Self::Module<'_>, VmiError> {
        Ok(LinuxModule::new(vmi, module))
    }

    /// Not supported yet.
    fn user_module(
        _vmi: VmiState<'_, Self>,
        _module: Va,
        _root: Pa,
    ) -> Result<Self::UserModule<'_>, VmiError> {
        Err(VmiError::NotSupported)
    }

    fn region(vmi: VmiState<'_, Self>, region: Va) -> Result<Self::Region<'_>, VmiError> {
        Ok(LinuxRegion::new(vmi, region))
    }

    fn syscall_argument(vmi: VmiState<Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(vmi, index)
    }

    fn function_argument(vmi: VmiState<Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(vmi, index)
    }

    fn function_return_value(vmi: VmiState<Self>) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(vmi)
    }

    /// Not supported yet.
    fn last_error(_vmi: VmiState<Self>) -> Result<Option<u32>, VmiError> {
        Err(VmiError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use isr::cache::Entry;

    use super::*;

    /// Opens the isr profile at the path in an environment variable.
    fn entry(variable: &str) -> Result<Entry, Box<dyn std::error::Error>> {
        let path = std::env::var(variable).map_err(|err| format!("{variable}: {err}"))?;
        Ok(Entry::new(PathBuf::from(path))?)
    }

    #[test]
    #[ignore = "needs VMI_OS_LINUX_PROFILE_6_8, the isr profile of a Linux 6.8 kernel"]
    fn profile_of_linux_6_8_uses_pcpu_hot() -> Result<(), Box<dyn std::error::Error>> {
        let entry = entry("VMI_OS_LINUX_PROFILE_6_8")?;
        let profile = entry.profile()?;
        let offsets = Offsets::new(&profile)?;
        let symbols = Symbols::new(&profile)?;

        assert!(matches!(
            CurrentTask::new(&offsets, &symbols)?,
            CurrentTask::ZeroBased(_)
        ));
        Ok(())
    }

    #[test]
    #[ignore = "needs VMI_OS_LINUX_PROFILE_7_0, the isr profile of a Linux 7.0 kernel"]
    fn profile_of_linux_7_0_uses_relocated_current_task() -> Result<(), Box<dyn std::error::Error>>
    {
        let entry = entry("VMI_OS_LINUX_PROFILE_7_0")?;
        let profile = entry.profile()?;
        let offsets = Offsets::new(&profile)?;
        let symbols = Symbols::new(&profile)?;

        assert!(offsets.pcpu_hot.is_none());
        assert!(matches!(
            CurrentTask::new(&offsets, &symbols)?,
            CurrentTask::Relocated(_)
        ));
        Ok(())
    }
}
