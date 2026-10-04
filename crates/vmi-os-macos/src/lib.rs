//! # macOS OS-specific VMI operations
//!
//! This crate provides functionality for introspecting macOS virtual
//! machines on Apple silicon, working in conjunction with the `vmi-core`
//! crate. It navigates the structures of the XNU kernel to enumerate
//! processes, threads, memory regions, open files and kernel extensions.
//!
//! ## Features
//!
//! - Locating the kernel collection and the kernel image in memory
//! - Per-segment relocation of profile symbols
//! - Process and thread introspection
//! - Memory region enumeration with mapped file paths
//! - Open file enumeration
//! - Kernel extension and dyld image enumeration
//! - Mach-O image parsing
//!
//! ## Kernel layout
//!
//! The kernel of macOS on Apple silicon is part of a kernel collection, an
//! `MH_FILESET` Mach-O image that bundles the kernel with its extensions.
//! Building the collection rearranges the segments of the kernel, and the
//! whole collection is slid at boot. The distance between a segment in
//! memory and the same segment in the Kernel Debug Kit therefore differs
//! from segment to segment. [`MacOs::find_kernel`] reads the segment table
//! of the kernel in memory, and [`MacOs::new`] relocates every profile
//! symbol by the segment that contains it.
//!
//! Kernel pointers may carry pointer authentication codes, which this crate
//! strips from every pointer it reads.
//!
//! ## Address spaces
//!
//! Kernel addresses translate through `TTBR1_EL1` of the registers in the
//! [`VmiState`]. The user half of a process translates through the table at
//! `task.map->pmap->ttep`, which the [`translation_root`] of a process
//! returns.
//!
//! ## Examples
//!
//! ```no_run
//! # use isr::cache::IsrCache;
//! # use vmi::{
//! #     VcpuId, VmiCore, VmiSession,
//! #     arch::arm64::{Arm64, Granule16KVa47},
//! #     driver::{VmiQueryRegisters, VmiRead},
//! #     os::{VmiOsProcess as _, macos::MacOs},
//! # };
//! #
//! # fn example<Driver>(
//! #     core: &VmiCore<Driver>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     Driver: VmiRead<Architecture = Arm64<Granule16KVa47>>
//! #           + VmiQueryRegisters<Architecture = Arm64<Granule16KVa47>>,
//! # {
//! let registers = core.registers(VcpuId(0))?;
//! let kernel_info = MacOs::find_kernel(core, &registers)?.expect("kernel information");
//!
//! let isr = IsrCache::new("cache")?;
//! let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
//! let profile = entry.profile()?;
//!
//! let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
//! let session = VmiSession::new(core, &os);
//! let vmi = session.with_registers(&registers);
//!
//! for process in vmi.os().processes()? {
//!     let process = process?;
//!     println!("{} {}", process.id()?, process.name()?);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`VmiState`]: vmi_core::VmiState
//! [`translation_root`]: vmi_core::os::VmiOsProcess::translation_root

use std::cell::OnceCell;

use isr_core::Profile;
use vmi_core::{
    AccessContext, Architecture, Pa, Va, VmiCore, VmiDriver, VmiError, VmiState,
    driver::VmiRead,
    os::{ProcessObject, ThreadObject, VmiOs},
};
use vmi_macros::derive_trait_from_impl;

mod arch;
pub use self::arch::ArchAdapter;

mod comps;
pub use self::comps::{
    MacOsFileKind, MacOsImage, MacOsMapped, MacOsModule, MacOsOpenFile, MacOsProcess,
    MacOsProcessArguments, MacOsRegion, MacOsThread, MacOsUserModule, MacOsVnode,
};

mod error;
pub use self::error::MacOsError;

mod iter;
pub use self::iter::{ListIterator, MapEntryIterator, QueueIterator};

mod macho;

mod offsets;
use self::offsets::{Offsets, Symbols};

mod relocation;
use self::relocation::KernelRelocations;

/// Upper bound on the number of loaded kernel extension summaries.
const MAX_KEXT_SUMMARIES: u32 = 4096;

/// Upper bound on the size of `struct proc`, in bytes.
const MAX_PROC_STRUCT_SIZE: u64 = 0x10000;

/// VMI operations for the macOS operating system.
///
/// `MacOs` provides methods and utilities for introspecting a macOS virtual
/// machine on Apple silicon. It encapsulates XNU-specific knowledge and
/// operations, allowing for high-level interactions with the guest OS
/// structures and processes.
///
/// # Usage
///
/// Locate the kernel with [`find_kernel`], load the profile that matches
/// its version and UUID, and create the instance with [`new`]:
///
/// ```no_run
/// use isr::cache::IsrCache;
/// use vmi::{
///     VcpuId, VmiCore,
///     arch::arm64::{Arm64, Granule16KVa47},
///     driver::{VmiQueryRegisters, VmiRead},
///     os::macos::MacOs,
/// };
///
/// # fn example<Driver>(
/// #     driver: Driver
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiRead<Architecture = Arm64<Granule16KVa47>>
/// #           + VmiQueryRegisters<Architecture = Arm64<Granule16KVa47>>,
/// # {
/// let core = VmiCore::new(driver)?;
/// let registers = core.registers(VcpuId(0))?;
///
/// // Locate the kernel to find out which profile to load.
/// let kernel_info = MacOs::find_kernel(&core, &registers)?.expect("kernel information");
///
/// // Load the profile from the Kernel Debug Kit of the kernel.
/// let isr = IsrCache::new("cache")?;
/// let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
/// let profile = entry.profile()?;
///
/// let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
/// # Ok(())
/// # }
/// ```
///
/// [`find_kernel`]: Self::find_kernel
/// [`new`]: Self::new
pub struct MacOs<Driver>
where
    Driver: VmiDriver,
{
    /// Structure offsets from the profile.
    offsets: Offsets,

    /// Symbols relocated to their runtime addresses.
    symbols: Symbols,

    /// Address of the kernel `MH_EXECUTE` header.
    kernel_image_base: Va,

    /// Address of the kernel collection `MH_FILESET` header.
    kernel_collection_base: Va,

    /// `LC_UUID` of the kernel.
    kernel_uuid: [u8; 16],

    /// XNU version string.
    kernel_version: String,

    /// Size of `struct proc`, read on first use.
    proc_struct_size: OnceCell<u64>,

    /// Ties the instance to the driver type.
    _marker: std::marker::PhantomData<Driver>,
}

/// Information about the macOS kernel found in memory.
#[derive(Debug, Clone)]
pub struct MacOsKernelInformation {
    /// Address of the `MH_FILESET` header of the kernel collection.
    pub kernel_collection_base: Va,

    /// Address of the `MH_EXECUTE` header of the kernel.
    pub base_address: Va,

    /// `LC_UUID` of the kernel, which identifies its Kernel Debug Kit.
    pub uuid: [u8; 16],

    /// XNU version string, such as `Darwin Kernel Version 27.0.0: ...`.
    pub version: String,

    /// Segments of the kernel at their runtime addresses, in load command
    /// order.
    pub segments: Vec<MacOsSegment>,
}

/// A segment of a Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsSegment {
    /// Segment name, such as `__TEXT`.
    pub name: String,

    /// Runtime address of the segment.
    pub address: Va,

    /// Size of the segment in memory, in bytes.
    pub size: u64,
}

macro_rules! offset {
    ($vmi:expr, $field:ident) => {
        &$vmi.underlying_os().offsets.$field
    };
}

pub(crate) use offset;

macro_rules! symbol {
    ($vmi:expr, $field:ident) => {
        Va($vmi.underlying_os().symbols.$field)
    };
}

macro_rules! this {
    ($vmi:expr) => {
        $vmi.underlying_os()
    };
}

#[derive_trait_from_impl(MacOsExt)]
impl<Driver> MacOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new `MacOs` instance.
    ///
    /// Relocates the profile symbols to their runtime addresses using the
    /// kernel segments in `kernel_info`. Fails when a segment of the profile
    /// has no counterpart in memory, or when a required symbol or structure
    /// is missing from the profile. No guest memory is read.
    pub fn new(profile: &Profile, kernel_info: &MacOsKernelInformation) -> Result<Self, VmiError> {
        let relocations = KernelRelocations::new(
            profile
                .segments()
                .map(|segment| (segment.name, segment.address, segment.size)),
            &kernel_info.segments,
        )?;

        Ok(Self {
            offsets: Offsets::new(profile)?,
            symbols: relocate_symbols(Symbols::new(profile)?, &relocations)?,
            kernel_image_base: kernel_info.base_address,
            kernel_collection_base: kernel_info.kernel_collection_base,
            kernel_uuid: kernel_info.uuid,
            kernel_version: kernel_info.version.clone(),
            proc_struct_size: OnceCell::new(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Locates the macOS kernel in memory based on the CPU registers.
    /// This function is architecture-specific.
    ///
    /// On ARM64, the kernel collection is located by reading the virtual
    /// memory page by page backwards from `VBAR_EL1` until an `MH_FILESET`
    /// header that contains the `com.apple.kernel` image is found.
    pub fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<MacOsKernelInformation>, VmiError> {
        Driver::Architecture::find_kernel(vmi, registers)
    }

    /// Returns the address of the kernel collection `MH_FILESET` header.
    pub fn kernel_collection_base(vmi: VmiState<Self>) -> Va {
        this!(vmi).kernel_collection_base
    }

    /// Returns the `LC_UUID` of the kernel.
    pub fn kernel_uuid(vmi: VmiState<Self>) -> [u8; 16] {
        this!(vmi).kernel_uuid
    }

    /// Reads a pointer from kernel memory and strips its tag bits.
    pub fn read_pointer(vmi: VmiState<Self>, va: Va) -> Result<Va, VmiError> {
        Ok(Driver::Architecture::canonical_address(vmi.read_u64(va)?))
    }

    /// Reads a pointer in the given access context and strips its tag bits.
    pub fn read_pointer_in(
        vmi: VmiState<Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Va, VmiError> {
        Ok(Driver::Architecture::canonical_address(
            vmi.read_u64_in(ctx)?,
        ))
    }

    /// Returns the size of `struct proc`.
    ///
    /// # Notes
    ///
    /// The value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// XNU allocates `struct proc` and `struct task` together, with the task
    /// at offset `proc_struct_size`. The size is computed as
    /// `kernel_task - kernproc`, the distance between the task and the
    /// process of the kernel.
    pub fn proc_struct_size(vmi: VmiState<Self>) -> Result<u64, VmiError> {
        if let Some(size) = this!(vmi).proc_struct_size.get() {
            return Ok(*size);
        }

        let kernproc = Self::read_pointer(vmi, symbol!(vmi, kernproc))?;
        let kernel_task = Self::read_pointer(vmi, symbol!(vmi, kernel_task))?;

        let size = match kernel_task.0.checked_sub(kernproc.0) {
            Some(size) if size > 0 && size <= MAX_PROC_STRUCT_SIZE => size,
            _ => return Err(MacOsError::CorruptedStruct("kernel_task").into()),
        };

        Ok(*this!(vmi).proc_struct_size.get_or_init(|| size))
    }

    /// Returns the address of the root vnode of the file system hierarchy.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `rootvnode` symbol.
    pub fn rootvnode(vmi: VmiState<Self>) -> Result<Va, VmiError> {
        Self::read_pointer(vmi, symbol!(vmi, rootvnode))
    }
}

impl<Driver> VmiOs for MacOs<Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Architecture = Driver::Architecture;
    type Driver = Driver;

    type Process<'a> = MacOsProcess<'a, Driver>;
    type Thread<'a> = MacOsThread<'a, Driver>;
    type Image<'a> = MacOsImage<'a, Driver>;
    type Module<'a> = MacOsModule<'a, Driver>;
    type UserModule<'a> = MacOsUserModule<'a, Driver>;
    type Region<'a> = MacOsRegion<'a, Driver>;
    type Mapped<'a> = MacOsMapped<'a, Driver>;

    /// Returns the address of the kernel `MH_EXECUTE` header.
    fn kernel_image_base(vmi: VmiState<Self>) -> Result<Va, VmiError> {
        Ok(this!(vmi).kernel_image_base)
    }

    /// Returns the XNU version string.
    fn kernel_information_string(vmi: VmiState<Self>) -> Result<String, VmiError> {
        Ok(this!(vmi).kernel_version.clone())
    }

    /// Returns `false`.
    ///
    /// XNU on ARM64 translates the kernel half of the address space through
    /// `TTBR1_EL1` and the user half through the `TTBR0_EL1` tables of each
    /// process. There is no separate set of user page tables with a reduced
    /// kernel mapping to report.
    fn kpti_enabled(_vmi: VmiState<Self>) -> Result<bool, VmiError> {
        Ok(false)
    }

    /// Returns an iterator over the loaded kernel extensions.
    ///
    /// # Implementation Details
    ///
    /// Iterates over the summaries of `gLoadedKextSummaries`, the table
    /// that the kernel maintains for debuggers. The kernel itself is not
    /// part of the table.
    fn modules<'a>(
        vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        let header = offset!(vmi, _loaded_kext_summary_header);
        let summary = offset!(vmi, _loaded_kext_summary);

        let summaries = Self::read_pointer(vmi, symbol!(vmi, gLoadedKextSummaries))?;

        let (count, entry_size) = if summaries.is_null() {
            (0, 0)
        }
        else {
            let count = vmi.read_u32(summaries + header.numSummaries.offset())?;
            let entry_size = vmi.read_u32(summaries + header.entry_size.offset())? as u64;

            if count > MAX_KEXT_SUMMARIES {
                return Err(MacOsError::CorruptedStruct("numSummaries").into());
            }

            if entry_size < summary.effective_len() as u64 {
                return Err(MacOsError::CorruptedStruct("entry_size").into());
            }

            (count, entry_size)
        };

        let first = summaries + header.summaries.offset();
        Ok((0..count as u64)
            .map(move |index| Ok(MacOsModule::new(vmi, first + index * entry_size))))
    }

    /// Returns an iterator over all processes.
    ///
    /// # Implementation Details
    ///
    /// Iterates over the `allproc` list through `proc.p_list`. The list
    /// holds the live processes, including `kernel_task`. Processes that
    /// exited but were not reaped yet live on the `zombproc` list instead
    /// and are not included.
    fn processes<'a>(
        vmi: VmiState<'a, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + use<'a, Driver>, VmiError>
    {
        let proc = offset!(vmi, proc);

        // `allproc` is a `LIST_HEAD`, whose first member points to the
        // first process. `le_next` is the first member of `LIST_ENTRY`.
        let first = Self::read_pointer(vmi, symbol!(vmi, allproc))?;

        Ok(ListIterator::new(vmi, first, proc.p_list.offset())
            .map(move |result| result.map(|entry| MacOsProcess::new(vmi, ProcessObject(entry)))))
    }

    fn process(
        vmi: VmiState<'_, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        Ok(MacOsProcess::new(vmi, process))
    }

    /// Returns the process of the thread running on the current CPU.
    fn current_process(vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        Self::current_thread(vmi)?.process()
    }

    /// Returns the process of the kernel, `kernel_task`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to the `kernproc` symbol.
    fn system_process(vmi: VmiState<'_, Self>) -> Result<Self::Process<'_>, VmiError> {
        let kernproc = Self::read_pointer(vmi, symbol!(vmi, kernproc))?;
        Ok(MacOsProcess::new(vmi, ProcessObject(kernproc)))
    }

    fn thread(vmi: VmiState<'_, Self>, thread: ThreadObject) -> Result<Self::Thread<'_>, VmiError> {
        Ok(MacOsThread::new(vmi, thread))
    }

    /// Returns the thread running on the current CPU.
    fn current_thread(vmi: VmiState<'_, Self>) -> Result<Self::Thread<'_>, VmiError> {
        let thread = Driver::Architecture::current_thread(vmi);
        Ok(MacOsThread::new(vmi, ThreadObject(thread)))
    }

    /// Returns the Mach-O image at `image_base`, read through the
    /// translation root that the registers of `vmi` select for it.
    fn image(vmi: VmiState<'_, Self>, image_base: Va) -> Result<Self::Image<'_>, VmiError> {
        Ok(MacOsImage::new(
            vmi,
            image_base,
            vmi.translation_root(image_base),
        ))
    }

    fn module(vmi: VmiState<'_, Self>, module: Va) -> Result<Self::Module<'_>, VmiError> {
        Ok(MacOsModule::new(vmi, module))
    }

    fn user_module(
        vmi: VmiState<'_, Self>,
        module: Va,
        root: Pa,
    ) -> Result<Self::UserModule<'_>, VmiError> {
        Ok(MacOsUserModule::new(vmi, module, root))
    }

    fn region(vmi: VmiState<'_, Self>, region: Va) -> Result<Self::Region<'_>, VmiError> {
        Ok(MacOsRegion::new(vmi, region))
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

    /// Returns `None`.
    ///
    /// BSD system calls report errors through the return value, and `errno`
    /// is a per-thread variable of the C library in user space. The kernel
    /// keeps no last error value per thread.
    fn last_error(_vmi: VmiState<Self>) -> Result<Option<u32>, VmiError> {
        Ok(None)
    }
}

/// Relocates every symbol to its runtime address.
fn relocate_symbols(
    symbols: Symbols,
    relocations: &KernelRelocations,
) -> Result<Symbols, MacOsError> {
    let relocate = |address: u64| relocations.relocate(address).map(|va| va.0);
    let relocate_optional = |address: Option<u64>| address.map(relocate).transpose();

    Ok(Symbols {
        allproc: relocate(symbols.allproc)?,
        kernproc: relocate(symbols.kernproc)?,
        kernel_task: relocate(symbols.kernel_task)?,
        gLoadedKextSummaries: relocate(symbols.gLoadedKextSummaries)?,
        rootvnode: relocate(symbols.rootvnode)?,
        vnode_pager_ops: relocate(symbols.vnode_pager_ops)?,
        dyld_pager_ops: relocate_optional(symbols.dyld_pager_ops)?,
        shared_region_pager_ops: relocate_optional(symbols.shared_region_pager_ops)?,
        apple_protect_pager_ops: relocate_optional(symbols.apple_protect_pager_ops)?,
    })
}
