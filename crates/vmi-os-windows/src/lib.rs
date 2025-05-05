//! # Windows OS-specific VMI operations
//!
//! This crate provides functionality for introspecting Windows-based
//! virtual machines, working in conjunction with the `vmi-core` crate.
//! It offers abstractions and utilities for navigating Windows kernel
//! structures, analyzing processes and memory, and performing Windows-specific
//! VMI tasks.
//!
//! ## Features
//!
//! - Windows kernel structure parsing and navigation
//! - Process and thread introspection
//! - Memory management operations (VAD tree traversal, PFN database manipulation)
//! - Windows object handling (files, sections, etc.)
//! - PE file format parsing and analysis
//!
//! ## Safety Considerations
//!
//! Many operations in this crate require pausing the VM to ensure consistency.
//! Always pause the VM when performing operations that could be affected by
//! concurrent changes in the guest OS. Be aware of the Windows version you're
//! introspecting, as kernel structures may vary between versions. Handle errors
//! appropriately, as VMI operations can fail due to various reasons (e.g.,
//! invalid memory access, incompatible Windows version).
//!
//! ## Example
//!
//! ```no_run
//! # use vmi::{VmiCore, VmiDriver, os::windows::WindowsOs};
//! #
//! # fn example<Driver: VmiDriver>(
//! #     vmi: &VmiCore<Driver>,
//! #     _os: &WindowsOs<Driver>
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let _guard = vmi.pause_guard()?;
//! // Perform introspection operations here
//! // VM automatically resumes when `_guard` goes out of scope
//! # Ok(())
//! # }
//! ```
//!
//! Always consider the potential for race conditions and ensure you're
//! working with a consistent state of the guest OS.

// Allow Windows-specific naming conventions to be used throughout this module.
#![allow(
    non_snake_case,         // example: AlpcpSendMessage
    non_upper_case_globals, // example: StandbyPageList
)]

use std::{cell::RefCell, collections::HashMap};

use isr_core::Profile;
use once_cell::unsync::OnceCell;
use vmi_core::{
    AccessContext, Architecture, Gfn, Hex, Registers as _, Va, VmiCore, VmiDriver, VmiError,
    VmiState,
    os::{ProcessObject, ThreadObject, VmiOs, VmiOsThread},
};
use vmi_macros::derive_trait_from_impl;
use zerocopy::{FromBytes, IntoBytes};

mod arch;
use self::arch::ArchAdapter;

mod error;
pub use self::error::WindowsError;

mod iter;
pub use self::iter::{HandleTableEntryIterator, ListEntryIterator, TreeNodeIterator};

pub mod pe;
pub use self::pe::{CodeView, Pe, PeError};

mod offsets;
pub use self::offsets::{Offsets, OffsetsExt, Symbols}; // TODO: make private + remove offsets() & symbols() methods

mod comps;
pub use self::comps::{
    ParseObjectTypeError, WindowsControlArea, WindowsDirectoryObject, WindowsFileObject,
    WindowsHandleTable, WindowsHandleTableEntry, WindowsImage, WindowsModule, WindowsObject,
    WindowsObjectAttributes, WindowsObjectHeaderNameInfo, WindowsObjectType, WindowsObjectTypeKind,
    WindowsPeb, WindowsProcess, WindowsProcessParameters, WindowsRegion, WindowsSectionObject,
    WindowsSession, WindowsThread, WindowsWow64Kind,
};

/// VMI operations for the Windows operating system.
///
/// `WindowsOs` provides methods and utilities for introspecting a Windows-based
/// virtual machine. It encapsulates Windows-specific knowledge and operations,
/// allowing for high-level interactions with the guest OS structures and processes.
///
/// # Usage
///
/// Create an instance of [`WindowsOs`] using a [`Profile`] that contains information
/// about the specific Windows version being introspected:
///
/// ```no_run
/// use isr::cache::{IsrCache, JsonCodec};
/// use vmi::{VcpuId, VmiCore, VmiDriver, VmiError, os::windows::WindowsOs};
///
/// # fn example<Driver: VmiDriver>(
/// #     driver: Driver
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiDriver<Architecture = vmi_arch_amd64::Amd64>,
/// # {
/// // Setup VMI.
/// let core = VmiCore::new(driver)?;
///
/// // Try to find the kernel information.
/// // This is necessary in order to load the profile.
/// let kernel_info = {
///     let _guard = core.pause_guard()?;
///     let registers = core.registers(VcpuId(0))?;
///
///     WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
/// };
///
/// // Load the profile using the ISR library.
/// let isr = IsrCache::<JsonCodec>::new("cache")?;
/// let entry = isr.entry_from_codeview(kernel_info.codeview)?;
/// let profile = entry.profile()?;
///
/// // Create a new `WindowsOs` instance.
/// let os = WindowsOs::<Driver>::new(&profile)?;
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
/// - The behavior and accuracy of some methods may vary depending on the
///   Windows version being introspected. Always ensure your [`Profile`] matches
///   the guest OS version.
///
/// # Examples
///
/// Retrieving information about the current process:
///
/// ```no_run
/// # use vmi::{VcpuId, VmiDriver, VmiState, os::windows::WindowsOs};
/// #
/// # fn example<Driver: VmiDriver>(
/// #     vmi: &VmiState<Driver, WindowsOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiDriver<Architecture = vmi_arch_amd64::Amd64>,
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
/// # use vmi::{VcpuId, VmiDriver, VmiState, os::windows::WindowsOs};
/// #
/// # fn example<Driver: VmiDriver>(
/// #     vmi: &VmiState<Driver, WindowsOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiDriver<Architecture = vmi_arch_amd64::Amd64>,
/// # {
/// for process in vmi.os().processes()? {
///     println!("Process: {} (PID: {})", process.name()?, process.id()?);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Safety
///
/// While this struct doesn't use unsafe code directly, many of its methods
/// interact with raw memory of the guest OS. Incorrect usage can lead to
/// invalid memory access or misinterpretation of data. Always ensure you're
/// working with the correct memory regions and OS structures.
///
/// [`pause_guard`]: VmiCore::pause_guard
pub struct WindowsOs<Driver>
where
    Driver: VmiDriver,
{
    offsets: Offsets,
    symbols: Symbols,

    kernel_image_base: OnceCell<Va>,
    highest_user_address: OnceCell<Va>,
    object_root_directory: OnceCell<Va>, // _OBJECT_DIRECTORY*
    object_header_cookie: OnceCell<u8>,
    object_type_cache: RefCell<HashMap<Va, WindowsObjectTypeKind>>,
    object_type_cache2: RefCell<HashMap<WindowsObjectTypeKind, Va>>,
    object_type_name_cache: RefCell<HashMap<Va, String>>,

    ki_kva_shadow: OnceCell<bool>,
    mm_pfn_database: OnceCell<Va>, // _MMPFN*
    nt_build_lab: OnceCell<String>,
    nt_build_lab_ex: OnceCell<String>,

    _marker: std::marker::PhantomData<Driver>,
}

/// Information about the Windows kernel image.
#[derive(Debug)]
pub struct WindowsKernelInformation {
    /// Base virtual address where the kernel image is loaded.
    pub base_address: Va,

    /// Major version number of the Windows kernel.
    pub version_major: u16,

    /// Minor version number of the Windows kernel.
    pub version_minor: u16,

    /// CodeView debugging information for the kernel image.
    pub codeview: CodeView,
}

/// Represents a `_EXCEPTION_RECORD` structure.
#[derive(Debug)]
pub struct WindowsExceptionRecord {
    /// The `ExceptionCode` field of the exception record.
    ///
    /// The reason the exception occurred. This is the code generated by a
    /// hardware exception, or the code specified in the `RaiseException`
    /// function for a software-generated exception.
    pub code: u32,

    /// The `ExceptionFlags` field of the exception record.
    ///
    /// This member contains zero or more exception flags.
    pub flags: u32,

    /// The `ExceptionRecord` field of the exception record.
    ///
    /// A pointer to an associated `EXCEPTION_RECORD` structure.
    /// Exception records can be chained together to provide additional
    /// information when nested exceptions occur.
    pub record: Va,

    /// The `ExceptionAddress` field of the exception record.
    ///
    /// The address where the exception occurred.
    pub address: Va,

    /// The `ExceptionInformation` field of the exception record.
    ///
    /// An array of additional arguments that describe the exception.
    /// The number of elements in the array is determined by the `NumberParameters`
    /// field of the exception record.
    pub information: Vec<u64>,
}

macro_rules! offset {
    ($vmi:expr, $field:ident) => {
        &this!($vmi).offsets.$field
    };
}

macro_rules! symbol {
    ($vmi:expr, $field:ident) => {
        this!($vmi).symbols.$field
    };
}

macro_rules! this {
    ($vmi:expr) => {
        $vmi.underlying_os()
    };
}

#[derive_trait_from_impl(WindowsOsExt)]
#[expect(non_snake_case, non_upper_case_globals)]
impl<Driver> WindowsOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// 32-bit current process pseudo-handle (-1).
    pub const NtCurrentProcess32: u64 = 0xffff_ffff;

    /// 64-bit current process pseudo-handle (-1).
    pub const NtCurrentProcess64: u64 = 0xffff_ffff_ffff_ffff;

    /// 32-bit current thread pseudo-handle (-2).
    pub const NtCurrentThread32: u64 = 0xffff_fffe;

    /// 64-bit current thread pseudo-handle (-2).
    pub const NtCurrentThread64: u64 = 0xffff_ffff_ffff_fffe;

    /// Creates a new `WindowsOs` instance.
    pub fn new(profile: &Profile) -> Result<Self, VmiError> {
        Self::create(profile, OnceCell::new())
    }

    /// Creates a new `WindowsOs` instance with a known kernel base address.
    pub fn with_kernel_base(profile: &Profile, kernel_base: Va) -> Result<Self, VmiError> {
        Self::create(profile, OnceCell::with_value(kernel_base))
    }

    fn create(profile: &Profile, kernel_image_base: OnceCell<Va>) -> Result<Self, VmiError> {
        Ok(Self {
            offsets: Offsets::new(profile)?,
            symbols: Symbols::new(profile)?,
            kernel_image_base,
            highest_user_address: OnceCell::new(),
            object_root_directory: OnceCell::new(),
            object_header_cookie: OnceCell::new(),
            object_type_cache: RefCell::new(HashMap::new()),
            object_type_cache2: RefCell::new(HashMap::new()),
            object_type_name_cache: RefCell::new(HashMap::new()),
            ki_kva_shadow: OnceCell::new(),
            mm_pfn_database: OnceCell::new(),
            nt_build_lab: OnceCell::new(),
            nt_build_lab_ex: OnceCell::new(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns a reference to the Windows-specific memory offsets.
    pub fn offsets(vmi: VmiState<Driver, Self>) -> &Offsets {
        &this!(vmi).offsets
    }

    /// Returns a reference to the Windows-specific symbols.
    pub fn symbols(vmi: VmiState<Driver, Self>) -> &Symbols {
        &this!(vmi).symbols
    }

    /// Locates the Windows kernel in memory based on the CPU registers.
    /// This function is architecture-specific.
    ///
    /// On AMD64, the kernel is located by taking the `MSR_LSTAR` value and
    /// reading the virtual memory page by page backwards until the `MZ` header
    /// is found.
    pub fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError> {
        Driver::Architecture::find_kernel(vmi, registers)
    }

    /// Returns the kernel information string.
    ///
    /// # Notes
    ///
    /// The kernel information string is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `NtBuildLab` symbol.
    pub fn kernel_information_string_ex(
        vmi: VmiState<Driver, Self>,
    ) -> Result<Option<String>, VmiError> {
        let NtBuildLabEx = match symbol!(vmi, NtBuildLabEx) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        Ok(Some(
            this!(vmi)
                .nt_build_lab_ex
                .get_or_try_init(|| {
                    let kernel_image_base = Self::kernel_image_base(vmi)?;
                    vmi.read_string(kernel_image_base + NtBuildLabEx)
                })
                .cloned()?,
        ))
    }

    /// Checks if the given handle is a kernel handle.
    ///
    /// A kernel handle is a handle with the highest bit set.
    pub fn is_kernel_handle(vmi: VmiState<Driver, Self>, handle: u64) -> Result<bool, VmiError> {
        const KERNEL_HANDLE_MASK32: u64 = 0x8000_0000;
        const KERNEL_HANDLE_MASK64: u64 = 0xffff_ffff_8000_0000;

        match vmi.registers().address_width() {
            4 => Ok(handle & KERNEL_HANDLE_MASK32 == KERNEL_HANDLE_MASK32),
            8 => Ok(handle & KERNEL_HANDLE_MASK64 == KERNEL_HANDLE_MASK64),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Returns the lowest user-mode address.
    ///
    /// This method returns a constant value (0x10000) representing the lowest
    /// address that can be used by user-mode applications in Windows.
    ///
    /// # Notes
    ///
    /// * Windows creates a `NO_ACCESS` VAD (Virtual Address Descriptor) for the first 64KB
    ///   of virtual memory. This means the VA range 0-0x10000 is off-limits for usage.
    /// * This behavior is consistent across all Windows versions from XP through
    ///   recent Windows 11, and applies to x86, x64, and ARM64 architectures.
    /// * Many Windows APIs leverage this fact to determine whether an input argument
    ///   is a pointer or not. Here are two notable examples:
    ///
    ///   1. The `FindResource()` function accepts an `lpName` parameter of type `LPCTSTR`,
    ///      which can be either:
    ///      - A pointer to a valid string
    ///      - A value created by `MAKEINTRESOURCE(ID)`
    ///
    ///         This allows `FindResource()` to accept `WORD` values (unsigned shorts) with
    ///         a maximum value of 0xFFFF, distinguishing them from valid memory addresses.
    ///
    ///   2. The `AddAtom()` function similarly accepts an `lpString` parameter of type `LPCTSTR`.
    ///      This parameter can be:
    ///      - A pointer to a null-terminated string (max 255 bytes)
    ///      - An integer atom converted using the `MAKEINTATOM(ID)` macro
    ///
    ///   In both cases, the API can distinguish between valid pointers (which will be
    ///   above 0x10000) and integer values (which will be below 0x10000), allowing
    ///   for flexible parameter usage without ambiguity.
    pub fn lowest_user_address(_vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        Ok(Va(0x10000))
    }

    /// Returns the highest user-mode address.
    ///
    /// This method reads the highest user-mode address from the Windows kernel.
    /// The value is cached after the first read for performance.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `MmHighestUserAddress` symbol.
    pub fn highest_user_address(vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        this!(vmi)
            .highest_user_address
            .get_or_try_init(|| {
                let MmHighestUserAddress =
                    Self::kernel_image_base(vmi)? + symbol!(vmi, MmHighestUserAddress);

                vmi.read_va_native(MmHighestUserAddress)
            })
            .copied()
    }

    /// Checks if a given address is a valid user-mode address.
    ///
    /// This method determines whether the provided address falls within
    /// the range of valid user-mode addresses in Windows.
    pub fn is_valid_user_address(
        vmi: VmiState<Driver, Self>,
        address: Va,
    ) -> Result<bool, VmiError> {
        let lowest_user_address = Self::lowest_user_address(vmi)?;
        let highest_user_address = Self::highest_user_address(vmi)?;

        Ok(address >= lowest_user_address && address <= highest_user_address)
    }

    /// Returns the virtual address of the current Kernel Processor Control
    /// Region (KPCR).
    ///
    /// The KPCR is a per-processor data structure in Windows that contains
    /// critical information about the current processor state. This method
    /// returns the virtual address of the KPCR for the current processor.
    pub fn current_kpcr(vmi: VmiState<Driver, Self>) -> Va {
        Driver::Architecture::current_kpcr(vmi)
    }

    /// Returns information from an exception record at the specified address.
    ///
    /// This method reads and parses an `EXCEPTION_RECORD` structure from
    /// memory, providing detailed information about an exception that has
    /// occurred in the system. The returned [`WindowsExceptionRecord`]
    /// contains data such as the exception code, flags, and related memory
    /// addresses.
    pub fn exception_record(
        vmi: VmiState<Driver, Self>,
        address: Va,
    ) -> Result<WindowsExceptionRecord, VmiError> {
        #[repr(C)]
        #[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
        #[allow(non_camel_case_types, non_snake_case)]
        struct _EXCEPTION_RECORD {
            ExceptionCode: u32,
            ExceptionFlags: u32,
            ExceptionRecord: u64,
            ExceptionAddress: u64,
            NumberParameters: u64,
            ExceptionInformation: [u64; 15],
        }

        let record = vmi.read_struct::<_EXCEPTION_RECORD>(address)?;

        Ok(WindowsExceptionRecord {
            code: record.ExceptionCode,
            flags: record.ExceptionFlags,
            record: record.ExceptionRecord.into(),
            address: record.ExceptionAddress.into(),
            information: record.ExceptionInformation
                [..u64::min(record.NumberParameters, 15) as usize]
                .to_vec(),
        })
    }

    /// Returns the last status value for the current thread.
    ///
    /// In Windows, the last status value is typically used to store error codes
    /// or success indicators from system calls. This method reads this value
    /// from the Thread Environment Block (TEB) of the current thread, providing
    /// insight into the outcome of recent operations performed by the thread.
    ///
    /// Returns `None` if the TEB is not available.
    ///
    /// # Notes
    ///
    /// `LastStatusValue` is a `NTSTATUS` value, whereas `LastError` is a Win32
    /// error code. The two values are related but not identical. You can obtain
    /// the Win32 error code by calling
    /// [`VmiOs::last_error`](crate::VmiOs::last_error).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `NtCurrentTeb()->LastStatusValue`.
    pub fn last_status(vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        let KTHREAD = offset!(vmi, _KTHREAD);
        let TEB = offset!(vmi, _TEB);

        let current_thread = Self::current_thread(vmi)?.object()?;
        let teb = vmi.read_va_native(current_thread.0 + KTHREAD.Teb.offset())?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(teb + TEB.LastStatusValue.offset())?;
        Ok(Some(result))
    }

    /// Returns the virtual address of the Page Frame Number (PFN) database.
    ///
    /// The PFN database is a critical data structure in Windows memory management,
    /// containing information about each physical page in the system.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `MmPfnDatabase` symbol.
    fn pfn_database(vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        let MmPfnDatabase = symbol!(vmi, MmPfnDatabase);

        this!(vmi)
            .mm_pfn_database
            .get_or_try_init(|| {
                let kernel_image_base = Self::kernel_image_base(vmi)?;
                vmi.read_va_native(kernel_image_base + MmPfnDatabase)
            })
            .copied()
    }

    fn modify_pfn_reference_count(
        vmi: VmiState<Driver, Self>,
        pfn: Gfn,
        increment: i16,
    ) -> Result<Option<u16>, VmiError> {
        let MMPFN = offset!(vmi, _MMPFN);

        // const ZeroedPageList: u16 = 0;
        // const FreePageList: u16 = 1;
        const StandbyPageList: u16 = 2; //this list and before make up available pages.
        const ModifiedPageList: u16 = 3;
        const ModifiedNoWritePageList: u16 = 4;
        // const BadPageList: u16 = 5;
        const ActiveAndValid: u16 = 6;
        // const TransitionPage: u16 = 7;

        let pfn = Self::pfn_database(vmi)? + u64::from(pfn) * MMPFN.len() as u64;

        //
        // In the _MMPFN structure, the fields are like this:
        //
        // ```c
        // struct _MMPFN {
        //     ...
        //     union {
        //         USHORT ReferenceCount;
        //         struct {
        //             UCHAR PageLocation : 3;
        //             ...
        //         } e1;
        //         ...
        //     } u3;
        // };
        // ```
        //
        // On the systems tested (Win7 - Win11), the `PageLocation` is right
        // after `ReferenceCount`. We can read the value of both fields at once.
        //

        debug_assert_eq!(MMPFN.ReferenceCount.size(), 2);
        debug_assert_eq!(
            MMPFN.ReferenceCount.offset() + MMPFN.ReferenceCount.size(),
            MMPFN.PageLocation.offset()
        );
        debug_assert_eq!(MMPFN.PageLocation.bit_position(), 0);
        debug_assert_eq!(MMPFN.PageLocation.bit_length(), 3);

        let pfn_value = vmi.read_u32(pfn + MMPFN.ReferenceCount.offset())?;
        let flags = (pfn_value >> 16) as u16;
        let ref_count = (pfn_value & 0xFFFF) as u16;

        let page_location = flags & 7;

        tracing::debug!(
            %pfn,
            ref_count,
            flags = %Hex(flags),
            page_location,
            increment,
            "Modifying PFN reference count"
        );

        //
        // Make sure the page is good (when coming from hibernate/standby pages
        // can be in modified state).
        //

        if !matches!(
            page_location,
            StandbyPageList | ModifiedPageList | ModifiedNoWritePageList | ActiveAndValid
        ) {
            tracing::warn!(
                %pfn,
                ref_count,
                flags = %Hex(flags),
                page_location,
                increment,
                "Page is not active and valid"
            );
            return Ok(None);
        }

        if ref_count == 0 {
            tracing::warn!(
                %pfn,
                ref_count,
                flags = %Hex(flags),
                page_location,
                increment,
                "Page is not initialized"
            );
            return Ok(None);
        }

        let new_ref_count = match ref_count.checked_add_signed(increment) {
            Some(new_ref_count) => new_ref_count,
            None => {
                tracing::warn!(
                    %pfn,
                    ref_count,
                    flags = %Hex(flags),
                    page_location,
                    increment,
                    "Page is at maximum reference count"
                );
                return Ok(None);
            }
        };

        tracing::debug!(pfn_value, new_ref_count, "xxx before");
        vmi.write_u16(pfn + MMPFN.ReferenceCount.offset(), new_ref_count)?;
        tracing::debug!(pfn_value, new_ref_count, "xxx after");

        Ok(Some(new_ref_count))
    }

    /// Increments the reference count of a Page Frame Number (PFN).
    ///
    /// This method is used to "lock" a physical page by increasing its
    /// reference count, preventing it from being paged out or reallocated.
    ///
    /// Returns the new reference count if successful, or `None` if the
    /// operation failed (e.g., if the page is not in a valid state).
    ///
    /// # Implementation Details
    ///
    /// The method works by:
    /// 1. Locating the `_MMPFN` structure for the given PFN within the `MmPfnDatabase`.
    /// 2. Incrementing the `ReferenceCount` member of the `_MMPFN` structure.
    ///
    /// # Warning
    ///
    /// This function can potentially cause race conditions if the virtual machine
    /// is not paused during its execution. It is strongly recommended to pause
    /// the virtual machine before calling this function and resume it afterwards.
    ///
    /// Failure to pause the VM may result in inconsistent state or potential
    /// crashes if the page is concurrently modified by the guest OS.
    ///
    /// # Examples:
    ///
    /// ```no_run
    /// # use vmi::{
    /// #     arch::amd64::{Amd64, Registers},
    /// #     os::windows::WindowsOs,
    /// #     Architecture, Gfn, VmiCore, VmiDriver, VmiError,
    /// # };
    /// #
    /// # fn example<Driver>(
    /// #     vmi: &VmiCore<Driver>,
    /// #     os: &WindowsOs<Driver>,
    /// #     registers: &Registers,
    /// #     pfn: Gfn,
    /// # ) -> Result<(), VmiError>
    /// # where
    /// #   Driver: VmiDriver<Architecture = Amd64>,
    /// # {
    /// let _pause_guard = vmi.pause_guard()?;
    /// os.lock_pfn(pfn)?;
    /// // The VM will automatically resume when `_guard` goes out of scope
    /// # Ok(())
    /// # }
    /// ```
    pub fn lock_pfn(vmi: VmiState<Driver, Self>, pfn: Gfn) -> Result<Option<u16>, VmiError> {
        Self::modify_pfn_reference_count(vmi, pfn, 1)
    }

    /// Decrements the reference count of a Page Frame Number (PFN).
    ///
    /// This method is used to "unlock" a physical page by decreasing its
    /// reference count, potentially allowing it to be paged out or reallocated
    /// if the count reaches zero.
    ///
    /// Returns the new reference count if successful, or `None` if the
    /// operation failed (e.g., if the page is not in a valid state).
    ///
    /// # Implementation Details
    ///
    /// The method works by:
    /// 1. Locating the `_MMPFN` structure for the given PFN within the `MmPfnDatabase`.
    /// 2. Decrementing the `ReferenceCount` member of the `_MMPFN` structure.
    ///
    /// # Warning
    ///
    /// This function can potentially cause race conditions if the virtual machine
    /// is not paused during its execution. It is strongly recommended to pause
    /// the virtual machine before calling this function and resume it afterwards.
    ///
    /// Failure to pause the VM may result in inconsistent state or potential
    /// crashes if the page is concurrently modified by the guest OS.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use vmi_arch_amd64::{Amd64, Registers};
    /// # use vmi_core::{Architecture, Gfn, VmiCore, VmiDriver, VmiError, VmiOs};
    /// # use vmi_os_windows::WindowsOs;
    /// #
    /// # fn example<Driver>(
    /// #     vmi: &VmiCore<Driver>,
    /// #     os: &WindowsOs<Driver>,
    /// #     registers: &Registers,
    /// #     pfn: Gfn,
    /// # ) -> Result<(), VmiError>
    /// # where
    /// #     Driver: VmiDriver<Architecture = Amd64>,
    /// # {
    /// let _pause_guard = vmi.pause_guard()?;
    /// os.unlock_pfn(pfn)?;
    /// // The VM will automatically resume when `_guard` goes out of scope
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock_pfn(vmi: VmiState<Driver, Self>, pfn: Gfn) -> Result<Option<u16>, VmiError> {
        Self::modify_pfn_reference_count(vmi, pfn, -1)
    }

    /// Returns the Windows object.
    pub fn object<'a>(
        vmi: VmiState<'a, Driver, Self>,
        va: Va,
    ) -> Result<WindowsObject<'a, Driver>, VmiError> {
        Ok(WindowsObject::new(vmi, va))
    }

    /// Returns a Windows object type for the given object kind.
    ///
    /// # Notes
    ///
    /// The object type is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// - `File` corresponds to `IoFileObjectType`.
    /// - `Job` corresponds to `PsJobType`.
    /// - `Key` corresponds to `CmKeyObjectType`.
    /// - `Process` corresponds to `PsProcessType`.
    /// - `Thread` corresponds to `PsThreadType`.
    /// - `Token` corresponds to `SeTokenObjectType`.
    /// - Other types are not supported.
    pub fn object_type<'a>(
        vmi: VmiState<'a, Driver, Self>,
        kind: WindowsObjectTypeKind,
    ) -> Result<WindowsObjectType<'a, Driver>, VmiError> {
        if let Some(va) = this!(vmi).object_type_cache2.borrow().get(&kind).copied() {
            return Ok(WindowsObjectType::new(vmi, va));
        }

        let symbol = match kind {
            WindowsObjectTypeKind::File => symbol!(vmi, IoFileObjectType),
            WindowsObjectTypeKind::Job => symbol!(vmi, PsJobType),
            WindowsObjectTypeKind::Key => symbol!(vmi, CmKeyObjectType),
            WindowsObjectTypeKind::Process => symbol!(vmi, PsProcessType),
            WindowsObjectTypeKind::Thread => symbol!(vmi, PsThreadType),
            WindowsObjectTypeKind::Token => symbol!(vmi, SeTokenObjectType),
            _ => return Err(VmiError::NotSupported),
        };

        let va = vmi.read_va(Self::kernel_image_base(vmi)? + symbol)?;
        this!(vmi).object_type_cache2.borrow_mut().insert(kind, va);

        Ok(WindowsObjectType::new(vmi, va))
    }

    /// Returns the root directory object for the Windows kernel.
    ///
    /// # Notes
    ///
    /// The object root directory is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `ObpRootDirectoryObject` symbol.
    pub fn object_root_directory<'a>(
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<WindowsDirectoryObject<'a, Driver>, VmiError> {
        let object_root_directory = this!(vmi)
            .object_root_directory
            .get_or_try_init(|| {
                let ObpRootDirectoryObject =
                    Self::kernel_image_base(vmi)? + symbol!(vmi, ObpRootDirectoryObject);

                vmi.read_va_native(ObpRootDirectoryObject)
            })
            .copied()?;

        Ok(WindowsDirectoryObject::new(vmi, object_root_directory))
    }

    /// Returns the object header cookie used for obfuscating object types.
    /// Returns `None` if the cookie is not present in the kernel image.
    ///
    /// # Notes
    ///
    /// Windows 10 introduced a security feature that obfuscates the type
    /// of kernel objects by XORing the `TypeIndex` field in the object header
    /// with a random cookie value. This method fetches that cookie, which is
    /// essential for correctly interpreting object headers in memory.
    ///
    /// The cookie is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `ObHeaderCookie` symbol.
    pub fn object_header_cookie(vmi: VmiState<Driver, Self>) -> Result<Option<u8>, VmiError> {
        let ObHeaderCookie = match symbol!(vmi, ObHeaderCookie) {
            Some(cookie) => cookie,
            None => return Ok(None),
        };

        Ok(Some(
            this!(vmi)
                .object_header_cookie
                .get_or_try_init(|| {
                    let kernel_image_base = Self::kernel_image_base(vmi)?;
                    vmi.read_u8(kernel_image_base + ObHeaderCookie)
                })
                .copied()?,
        ))
    }

    /// Returns the Windows object attributes.
    pub fn object_attributes<'a>(
        vmi: VmiState<'a, Driver, Self>,
        object_attributes: Va,
    ) -> Result<WindowsObjectAttributes<'a, Driver>, VmiError> {
        Ok(WindowsObjectAttributes::new(vmi, object_attributes))
    }

    /// Reads string of bytes from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u8>, VmiError> {
        Self::read_ansi_string_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string of bytes from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u8>, VmiError> {
        Self::read_ansi_string32_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string of bytes from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u8>, VmiError> {
        Self::read_ansi_string64_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_ansi_string_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_ansi_string32_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_ansi_string64_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u16>, VmiError> {
        Self::read_unicode_string_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u16>, VmiError> {
        Self::read_unicode_string32_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64_bytes(
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<Vec<u16>, VmiError> {
        Self::read_unicode_string64_bytes_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_unicode_string_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_unicode_string32_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64(vmi: VmiState<Driver, Self>, va: Va) -> Result<String, VmiError> {
        Self::read_unicode_string64_in(vmi, vmi.access_context(va))
    }

    /// Reads string of bytes from a 32-bit version of `_ANSI_STRING` or
    /// `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` or
    /// `_UNICODE_STRING` structures in 32-bit processes or WoW64 processes
    /// where pointers are 32 bits.
    fn read_string32_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 8];
        vmi.read_in(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);

        if string_length == 0 {
            return Ok(Vec::new());
        }

        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        if string_buffer == 0 {
            tracing::warn!(
                addr = %Hex(ctx.address),
                len = string_length,
                "String buffer is NULL"
            );

            return Ok(Vec::new());
        }

        ctx.address = string_buffer as u64;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read_in(ctx, &mut buffer)?;

        Ok(buffer)
    }

    /// Reads string of bytes from a 64-bit version of `_ANSI_STRING` or
    /// `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` or
    /// `_UNICODE_STRING` structures in 64-bit processes where pointers
    /// are 64 bits.
    fn read_string64_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 16];
        vmi.read_in(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);

        if string_length == 0 {
            return Ok(Vec::new());
        }

        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
            buffer[15],
        ]);

        if string_buffer == 0 {
            tracing::warn!(
                addr = %Hex(ctx.address),
                len = string_length,
                "String buffer is NULL"
            );

            return Ok(Vec::new());
        }

        ctx.address = string_buffer;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read_in(ctx, &mut buffer)?;

        Ok(buffer)
    }

    /// Reads string of bytes from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        match vmi.registers().address_width() {
            4 => Self::read_ansi_string32_bytes_in(vmi, ctx),
            8 => Self::read_ansi_string64_bytes_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string of bytes from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        Self::read_string32_in(vmi, ctx)
    }

    /// Reads string of bytes from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        Self::read_string64_in(vmi, ctx)
    }

    /// Reads string from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        match vmi.registers().address_width() {
            4 => Self::read_ansi_string32_in(vmi, ctx),
            8 => Self::read_ansi_string64_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf8_lossy(&Self::read_ansi_string32_bytes_in(vmi, ctx)?).into())
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf8_lossy(&Self::read_ansi_string64_bytes_in(vmi, ctx)?).into())
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u16>, VmiError> {
        match vmi.registers().address_width() {
            4 => Self::read_unicode_string32_bytes_in(vmi, ctx),
            8 => Self::read_unicode_string64_bytes_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u16>, VmiError> {
        let buffer = Self::read_string32_in(vmi, ctx)?;

        Ok(buffer
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>())
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64_bytes_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u16>, VmiError> {
        let buffer = Self::read_string64_in(vmi, ctx)?;

        Ok(buffer
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>())
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        match vmi.registers().address_width() {
            4 => Self::read_unicode_string32_in(vmi, ctx),
            8 => Self::read_unicode_string64_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf16_lossy(
            &Self::read_unicode_string32_bytes_in(vmi, ctx)?,
        ))
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64_in(
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        Ok(String::from_utf16_lossy(
            &Self::read_unicode_string64_bytes_in(vmi, ctx)?,
        ))
    }

    /// Returns an iterator over a doubly-linked list of `LIST_ENTRY` structures.
    ///
    /// This method is used to iterate over a doubly-linked list of `LIST_ENTRY`
    /// structures in memory. It returns an iterator that yields the virtual
    /// addresses of each `LIST_ENTRY` structure in the list.
    pub fn linked_list<'a>(
        vmi: VmiState<'a, Driver, Self>,
        list_head: Va,
        offset: u64,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + 'a, VmiError> {
        Ok(ListEntryIterator::new(vmi, list_head, offset))
    }
}

#[expect(non_snake_case)]
impl<Driver> VmiOs<Driver> for WindowsOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Process<'a> = WindowsProcess<'a, Driver>;
    type Thread<'a> = WindowsThread<'a, Driver>;
    type Image<'a> = WindowsImage<'a, Driver>;
    type Module<'a> = WindowsModule<'a, Driver>;
    type Region<'a> = WindowsRegion<'a, Driver>;
    type Mapped<'a> = WindowsControlArea<'a, Driver>;

    fn kernel_image_base(vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        Driver::Architecture::kernel_image_base(vmi)
    }

    fn kernel_information_string(vmi: VmiState<Driver, Self>) -> Result<String, VmiError> {
        this!(vmi)
            .nt_build_lab
            .get_or_try_init(|| {
                let NtBuildLab = symbol!(vmi, NtBuildLab);

                let kernel_image_base = Self::kernel_image_base(vmi)?;
                vmi.read_string(kernel_image_base + NtBuildLab)
            })
            .cloned()
    }

    /// Checks if Kernel Virtual Address Shadow (KVA Shadow) is enabled.
    ///
    /// KVA Shadow is a security feature introduced in Windows 10 that
    /// mitigates Meltdown and Spectre vulnerabilities by isolating
    /// kernel memory from user-mode processes.
    ///
    /// # Notes
    ///
    /// This value is cached after the first read.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `KiKvaShadow` symbol.
    fn kpti_enabled(vmi: VmiState<Driver, Self>) -> Result<bool, VmiError> {
        this!(vmi)
            .ki_kva_shadow
            .get_or_try_init(|| {
                let KiKvaShadow = symbol!(vmi, KiKvaShadow);

                let KiKvaShadow = match KiKvaShadow {
                    Some(KiKvaShadow) => KiKvaShadow,
                    None => return Ok(false),
                };

                let kernel_image_base = Self::kernel_image_base(vmi)?;
                Ok(vmi.read_u8(kernel_image_base + KiKvaShadow)? != 0)
            })
            .copied()
    }

    /// Returns an iterator over all loaded Windows Driver modules.
    ///
    /// This method returns an iterator over all loaded Windows Driver modules.
    /// It reads the `PsLoadedModuleList` symbol from the kernel image and
    /// iterates over the linked list of `KLDR_DATA_TABLE_ENTRY` structures
    /// representing each loaded module.
    fn modules(
        vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'_>, VmiError>> + '_, VmiError> {
        let PsLoadedModuleList = Self::kernel_image_base(vmi)? + symbol!(vmi, PsLoadedModuleList);
        let KLDR_DATA_TABLE_ENTRY = offset!(vmi, _KLDR_DATA_TABLE_ENTRY);

        Ok(ListEntryIterator::new(
            vmi,
            PsLoadedModuleList,
            KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.offset(),
        )
        .map(move |result| result.map(|entry| WindowsModule::new(vmi, entry))))
    }

    /// Returns an iterator over all Windows processes.
    ///
    /// This method returns an iterator over all Windows processes. It reads the
    /// `PsActiveProcessHead` symbol from the kernel image and iterates over the
    /// linked list of `EPROCESS` structures representing each process.
    fn processes(
        vmi: VmiState<'_, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'_>, VmiError>> + '_, VmiError> {
        let PsActiveProcessHead = Self::kernel_image_base(vmi)? + symbol!(vmi, PsActiveProcessHead);
        let EPROCESS = offset!(vmi, _EPROCESS);

        Ok(ListEntryIterator::new(
            vmi,
            PsActiveProcessHead,
            EPROCESS.ActiveProcessLinks.offset(),
        )
        .map(move |result| result.map(|entry| WindowsProcess::new(vmi, ProcessObject(entry)))))
    }

    fn process(
        vmi: VmiState<'_, Driver, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'_>, VmiError> {
        Ok(WindowsProcess::new(vmi, process))
    }

    /// Returns the current process.
    fn current_process(vmi: VmiState<'_, Driver, Self>) -> Result<Self::Process<'_>, VmiError> {
        Self::current_thread(vmi)?.attached_process()
    }

    /// Returns the system process.
    ///
    /// The system process is the first process created by the Windows kernel
    /// during system initialization. It is the parent process of all other
    /// processes in the system.
    fn system_process(vmi: VmiState<'_, Driver, Self>) -> Result<Self::Process<'_>, VmiError> {
        let PsInitialSystemProcess =
            Self::kernel_image_base(vmi)? + symbol!(vmi, PsInitialSystemProcess);

        let process = vmi.read_va_native(PsInitialSystemProcess)?;
        Ok(WindowsProcess::new(vmi, ProcessObject(process)))
    }

    fn thread(
        vmi: VmiState<'_, Driver, Self>,
        thread: ThreadObject,
    ) -> Result<Self::Thread<'_>, VmiError> {
        Ok(WindowsThread::new(vmi, thread))
    }

    /// Returns the current thread.
    fn current_thread(vmi: VmiState<'_, Driver, Self>) -> Result<Self::Thread<'_>, VmiError> {
        let KPCR = offset!(vmi, _KPCR);
        let KPRCB = offset!(vmi, _KPRCB);

        let kpcr = Self::current_kpcr(vmi);

        if kpcr.is_null() {
            return Err(WindowsError::CorruptedStruct("KPCR").into());
        }

        let addr = kpcr + KPCR.Prcb.offset() + KPRCB.CurrentThread.offset();
        let result = vmi.read_va_native(addr)?;

        if result.is_null() {
            return Err(WindowsError::CorruptedStruct("KPCR.Prcb.CurrentThread").into());
        }

        Ok(WindowsThread::new(vmi, ThreadObject(result)))
    }

    fn image(vmi: VmiState<'_, Driver, Self>, image_base: Va) -> Result<Self::Image<'_>, VmiError> {
        Ok(WindowsImage::new(vmi, image_base))
    }

    fn module(vmi: VmiState<'_, Driver, Self>, module: Va) -> Result<Self::Module<'_>, VmiError> {
        Ok(WindowsModule::new(vmi, module))
    }

    fn region(vmi: VmiState<'_, Driver, Self>, region: Va) -> Result<Self::Region<'_>, VmiError> {
        Ok(WindowsRegion::new(vmi, region))
    }

    fn syscall_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(vmi, index)
    }

    fn function_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(vmi, index)
    }

    fn function_return_value(vmi: VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(vmi)
    }

    fn last_error(vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        let KTHREAD = offset!(vmi, _KTHREAD);
        let TEB = offset!(vmi, _TEB);

        let current_thread = Self::current_thread(vmi)?.object()?;
        let teb = vmi.read_va_native(current_thread.0 + KTHREAD.Teb.offset())?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(teb + TEB.LastErrorValue.offset())?;

        Ok(Some(result))
    }
}
