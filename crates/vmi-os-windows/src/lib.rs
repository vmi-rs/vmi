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
    os::{ProcessObject, ThreadObject, VmiOs, VmiOsThread},
    AccessContext, Architecture, Gfn, Hex, Registers as _, Va, VmiCore, VmiDriver, VmiError,
    VmiState,
};
use vmi_macros::derive_trait_from_impl;
use zerocopy::{FromBytes, IntoBytes};

mod arch;
use self::arch::ArchAdapter;

mod iter;
pub use self::iter::{ListEntryIterator, TreeNodeIterator};

pub mod pe;
pub use self::pe::{CodeView, Pe, PeError};

mod offsets;
pub use self::offsets::{Offsets, OffsetsExt, Symbols}; // TODO: make private + remove offsets() & symbols() methods

mod image;
mod handle_table;
mod handle_table_entry;
pub(crate) mod macros;
mod module;
mod peb;
mod process;
mod region;
mod thread;
mod xobject;
pub use self::{
    handle_table::WindowsHandleTable,
    handle_table_entry::WindowsHandleTableEntry,
    image::WindowsImage,
    module::WindowsModule,
    peb::WindowsPeb,
    process::WindowsProcess,
    region::WindowsRegion,
    thread::WindowsThread,
    xobject::{
        WindowsObjectType, WindowsDirectoryObject, WindowsObject,
        WindowsObjectHeaderNameInfo, WindowsSectionObject,
    },
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
/// # use vmi::{VcpuId, VmiDriver, VmiSession, os::windows::WindowsOs};
/// #
/// # fn example<Driver: VmiDriver>(
/// #     vmi: &VmiSession<Driver, WindowsOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiDriver<Architecture = vmi_arch_amd64::Amd64>,
/// # {
/// let registers = vmi.registers(VcpuId(0))?;
/// let current_process = vmi.os().current_process(&registers)?;
/// let process_id = vmi.os().process_id(&registers, current_process)?;
/// let process_name = vmi.os().process_filename(&registers, current_process)?;
/// println!("Current process: {} (PID: {})", process_name, process_id);
/// # Ok(())
/// # }
/// ```
///
/// Enumerating all processes:
///
/// ```no_run
/// # use vmi::{VcpuId, VmiDriver, VmiSession, os::windows::WindowsOs};
/// #
/// # fn example<Driver: VmiDriver>(
/// #     vmi: &VmiSession<Driver, WindowsOs<Driver>>,
/// # ) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     Driver: VmiDriver<Architecture = vmi_arch_amd64::Amd64>,
/// # {
/// let registers = vmi.registers(VcpuId(0))?;
/// let processes = vmi.os().processes(&registers)?;
/// for process in processes {
///     println!("Process: {} (PID: {})", process.name, process.id);
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
    object_type_cache: RefCell<HashMap<Va, WindowsObjectType>>,

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

#[derive_trait_from_impl(WindowsOsExt)]
#[allow(non_snake_case, non_upper_case_globals)]
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
        Ok(Self {
            offsets: Offsets::new(profile)?,
            symbols: Symbols::new(profile)?,
            kernel_image_base: OnceCell::new(),
            highest_user_address: OnceCell::new(),
            object_root_directory: OnceCell::new(),
            object_header_cookie: OnceCell::new(),
            object_type_cache: RefCell::new(HashMap::new()),
            ki_kva_shadow: OnceCell::new(),
            mm_pfn_database: OnceCell::new(),
            nt_build_lab: OnceCell::new(),
            nt_build_lab_ex: OnceCell::new(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns a reference to the Windows-specific memory offsets.
    pub fn offsets(&self) -> &Offsets {
        &self.offsets
    }

    /// Returns a reference to the Windows-specific symbols.
    pub fn symbols(&self) -> &Symbols {
        &self.symbols
    }

    // region: Handle

    /// Checks if the given handle is a kernel handle.
    pub fn is_kernel_handle(
        &self,
        vmi: VmiState<Driver, Self>,
        handle: u64,
    ) -> Result<bool, VmiError> {
        const KERNEL_HANDLE_MASK32: u64 = 0x8000_0000;
        const KERNEL_HANDLE_MASK64: u64 = 0xffff_ffff_8000_0000;

        match vmi.registers().address_width() {
            4 => Ok(handle & KERNEL_HANDLE_MASK32 == KERNEL_HANDLE_MASK32),
            8 => Ok(handle & KERNEL_HANDLE_MASK64 == KERNEL_HANDLE_MASK64),
            _ => panic!("Unsupported address width"),
        }
    }

    // endregion: Handle

    // region: Kernel

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

    /// Retrieves the kernel information string.
    ///
    /// # Implementation Details
    ///
    /// The kernel information string is located by reading the `NtBuildLabEx`
    /// symbol from the kernel image.
    pub fn kernel_information_string_ex(
        &self,
        vmi: VmiState<Driver, Self>,
    ) -> Result<Option<String>, VmiError> {
        let NtBuildLabEx = match self.symbols.NtBuildLabEx {
            Some(offset) => offset,
            None => return Ok(None),
        };

        self.nt_build_lab_ex
            .get_or_try_init(|| {
                let kernel_image_base = self.kernel_image_base(vmi)?;
                vmi.read_string(kernel_image_base + NtBuildLabEx)
            })
            .cloned()
            .map(Some)
    }

    // endregion: Kernel

    // region: Memory

    /// Retrieves the virtual address of the Page Frame Number (PFN) database.
    ///
    /// The PFN database is a critical data structure in Windows memory management,
    /// containing information about each physical page in the system.
    ///
    /// # Implementation Details
    ///
    /// The PFN database is located by reading the `MmPfnDatabase` symbol from
    /// the kernel image.
    fn pfn_database(&self, vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        let MmPfnDatabase = self.symbols.MmPfnDatabase;

        self.mm_pfn_database
            .get_or_try_init(|| {
                let kernel_image_base = self.kernel_image_base(vmi)?;
                vmi.read_va_native(kernel_image_base + MmPfnDatabase)
            })
            .copied()
    }

    fn modify_pfn_reference_count(
        &self,
        vmi: VmiState<Driver, Self>,
        pfn: Gfn,
        increment: i16,
    ) -> Result<Option<u16>, VmiError> {
        let MMPFN = &self.offsets._MMPFN;

        // const ZeroedPageList: u16 = 0;
        // const FreePageList: u16 = 1;
        const StandbyPageList: u16 = 2; //this list and before make up available pages.
        const ModifiedPageList: u16 = 3;
        const ModifiedNoWritePageList: u16 = 4;
        // const BadPageList: u16 = 5;
        const ActiveAndValid: u16 = 6;
        // const TransitionPage: u16 = 7;

        let pfn = self.pfn_database(vmi)? + u64::from(pfn) * MMPFN.len() as u64;

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

        debug_assert_eq!(MMPFN.ReferenceCount.size, 2);
        debug_assert_eq!(
            MMPFN.ReferenceCount.offset + MMPFN.ReferenceCount.size,
            MMPFN.PageLocation.offset
        );
        debug_assert_eq!(MMPFN.PageLocation.bit_position, 0);
        debug_assert_eq!(MMPFN.PageLocation.bit_length, 3);

        let pfn_value = vmi.read_u32(pfn + MMPFN.ReferenceCount.offset)?;
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

        vmi.write_u16(pfn + MMPFN.ReferenceCount.offset, new_ref_count)?;

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
    pub fn lock_pfn(&self, vmi: VmiState<Driver, Self>, pfn: Gfn) -> Result<Option<u16>, VmiError> {
        self.modify_pfn_reference_count(vmi, pfn, 1)
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
    pub fn unlock_pfn(
        &self,
        vmi: VmiState<Driver, Self>,
        pfn: Gfn,
    ) -> Result<Option<u16>, VmiError> {
        self.modify_pfn_reference_count(vmi, pfn, -1)
    }

    // endregion: Memory

    // region: Misc

    /// Retrieves the virtual address of the current Kernel Processor Control
    /// Region (KPCR).
    ///
    /// The KPCR is a per-processor data structure in Windows that contains
    /// critical information about the current processor state. This method
    /// returns the virtual address of the KPCR for the current processor.
    pub fn current_kpcr(&self, vmi: VmiState<Driver, Self>) -> Va {
        Driver::Architecture::current_kpcr(vmi, self)
    }

    /// Extracts information from an exception record at the specified address.
    ///
    /// This method reads and parses an `EXCEPTION_RECORD` structure from
    /// memory, providing detailed information about an exception that has
    /// occurred in the system. The returned [`WindowsExceptionRecord`]
    /// contains data such as the exception code, flags, and related memory
    /// addresses.
    pub fn exception_record(
        &self,
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

    /// Retrieves the last status value for the current thread.
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
    /// ```c
    /// return NtCurrentTeb()->LastStatusValue;
    /// ```
    pub fn last_status(&self, vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        let KTHREAD = &self.offsets._KTHREAD;
        let TEB = &self.offsets._TEB;

        let current_thread = self.current_thread(vmi)?.object()?;
        let teb = vmi.read_va_native(current_thread.0 + KTHREAD.Teb.offset)?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(teb + TEB.LastStatusValue.offset)?;
        Ok(Some(result))
    }

    // endregion: Misc

    // region: Object

    /// Returns the object.
    pub fn __object<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        va: Va,
    ) -> Result<WindowsObject<'a, Driver>, VmiError> {
        Ok(WindowsObject::new(vmi, va))
    }

    /// Retrieves the root directory object for the Windows kernel.
    ///
    /// # Implementation Details
    ///
    /// The root directory object is located by reading the `ObpRootDirectoryObject`
    /// symbol from the kernel image.
    pub fn __object_root_directory<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<WindowsDirectoryObject<'a, Driver>, VmiError> {
        let object_root_directory = self
            .object_root_directory
            .get_or_try_init(|| {
                let ObpRootDirectoryObject =
                    self.kernel_image_base(vmi)? + self.symbols.ObpRootDirectoryObject;

                vmi.read_va_native(ObpRootDirectoryObject)
            })
            .copied()?;

        Ok(WindowsDirectoryObject::new(vmi, object_root_directory))
    }

    /// Retrieves the object header cookie used for obfuscating object types.
    /// Returns `None` if the cookie is not present in the kernel image.
    ///
    /// # Notes
    ///
    /// Windows 10 introduced a security feature that obfuscates the type
    /// of kernel objects by XORing the `TypeIndex` field in the object header
    /// with a random cookie value. This method fetches that cookie, which is
    /// essential for correctly interpreting object headers in memory.
    ///
    /// # Implementation Details
    ///
    /// The object header cookie is located by reading the `ObHeaderCookie`
    /// symbol from the kernel image.
    pub fn object_header_cookie(
        &self,
        vmi: VmiState<Driver, Self>,
    ) -> Result<Option<u8>, VmiError> {
        let ObHeaderCookie = match self.symbols.ObHeaderCookie {
            Some(cookie) => cookie,
            None => return Ok(None),
        };

        self.object_header_cookie
            .get_or_try_init(|| {
                let kernel_image_base = self.kernel_image_base(vmi)?;
                vmi.read_u8(kernel_image_base + ObHeaderCookie)
            })
            .copied()
            .map(Some)
    }

    /// Determines the type of a Windows kernel object.
    ///
    /// This method analyzes the object header of a given kernel object
    /// and returns its type (e.g., Process, Thread, File). It handles the
    /// obfuscation introduced by the object header cookie, ensuring accurate
    /// type identification even on systems with this security feature enabled.
    ///
    /// Returns `None` if the object type cannot be determined.
    pub fn object_type(
        &self,
        vmi: VmiState<Driver, Self>,
        object: Va,
    ) -> Result<Option<WindowsObjectType>, VmiError> {
        let ObTypeIndexTable = self.symbols.ObTypeIndexTable;
        let OBJECT_HEADER = &self.offsets._OBJECT_HEADER;
        let OBJECT_TYPE = &self.offsets._OBJECT_TYPE;

        let object_header = object - OBJECT_HEADER.Body.offset;
        let type_index = vmi.read_u8(object_header + OBJECT_HEADER.TypeIndex.offset)?;

        let index = match self.object_header_cookie(vmi)? {
            Some(cookie) => {
                //
                // TypeIndex ^ 2nd least significate byte of OBJECT_HEADER address ^
                // nt!ObHeaderCookie ref: https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a
                //

                let salt = (u64::from(object_header) >> 8) as u8;
                type_index ^ salt ^ cookie
            }
            None => type_index,
        };

        let index = index as u64;

        let kernel_image_base = self.kernel_image_base(vmi)?;
        let object_type = vmi.read_va_native(
            kernel_image_base + ObTypeIndexTable + index * 8, // REVIEW: replace 8 with registers.address_width()?
        )?;

        if let Some(typ) = self.object_type_cache.borrow().get(&object_type) {
            return Ok(Some(*typ));
        }

        let object_name = self.read_unicode_string(vmi, object_type + OBJECT_TYPE.Name.offset)?;

        let typ = match object_name.as_str() {
            "ALPC Port" => WindowsObjectType::AlpcPort,
            "DebugObject" => WindowsObjectType::DebugObject,
            "Device" => WindowsObjectType::Device,
            "Directory" => WindowsObjectType::Directory,
            "Driver" => WindowsObjectType::Driver,
            "Event" => WindowsObjectType::Event,
            "File" => WindowsObjectType::File,
            "Job" => WindowsObjectType::Job,
            "Key" => WindowsObjectType::Key,
            "Mutant" => WindowsObjectType::Mutant,
            "Port" => WindowsObjectType::Port,
            "Process" => WindowsObjectType::Process,
            "Section" => WindowsObjectType::Section,
            "SymbolicLink" => WindowsObjectType::SymbolicLink,
            "Thread" => WindowsObjectType::Thread,
            "Timer" => WindowsObjectType::Timer,
            "Token" => WindowsObjectType::Token,
            "Type" => WindowsObjectType::Type,
            _ => return Ok(None),
        };

        self.object_type_cache.borrow_mut().insert(object_type, typ);

        Ok(Some(typ))
    }

    /*
    /// Converts an `OBJECT_ATTRIBUTES` structure to an object name string.
    ///
    /// `OBJECT_ATTRIBUTES` is a structure used in many Windows system calls to
    /// specify an object. This method interprets that structure and extracts
    /// a meaningful name or path for the object. It handles both absolute and
    /// relative object names, considering the root directory if specified.
    ///
    /// Returns `None` if the `_OBJECT_ATTRIBUTES::ObjectName` field is `NULL`.
    pub fn object_attributes_to_object_name(
        &self,
        vmi: VmiState<Driver, Self>,
        process: ProcessObject,
        object_attributes: Va,
    ) -> Result<Option<String>, VmiError> {
        let OBJECT_ATTRIBUTES = &self.offsets._OBJECT_ATTRIBUTES;

        let object_name_address =
            vmi.read_va_native(object_attributes + OBJECT_ATTRIBUTES.ObjectName.offset)?;

        if object_name_address.is_null() {
            return Ok(None);
        }

        let object_name = self.read_unicode_string(vmi, object_name_address)?;

        let root_directory =
            vmi.read_va_native(object_attributes + OBJECT_ATTRIBUTES.RootDirectory.offset)?;

        if root_directory.is_null() {
            return Ok(Some(object_name));
        }

        let object = match self.handle_to_object(vmi, process, u64::from(root_directory))? {
            Some(object) => object,
            None => return Ok(Some(object_name)),
        };

        let root_name = match object {
            WindowsObject::File(file) => Some(file.filename),
            WindowsObject::Section(section) => match section.region.kind {
                OsRegionKind::Mapped(mapped) => mapped.path?,
                _ => None,
            },
        };

        match root_name {
            Some(root_name) => Ok(Some(format!("{root_name}\\{object_name}"))),
            None => Ok(Some(object_name)),
        }
    }
    */

    // endregion: Object

    // region: String

    /// Reads string from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_ansi_string_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_ansi_string32_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_ansi_string64_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_unicode_string_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_unicode_string32_in(vmi, vmi.access_context(va))
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64(
        &self,
        vmi: VmiState<Driver, Self>,
        va: Va,
    ) -> Result<String, VmiError> {
        self.read_unicode_string64_in(vmi, vmi.access_context(va))
    }

    /// Reads string buffer from a 32-bit version of `_ANSI_STRING` or
    /// `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` or
    /// `_UNICODE_STRING` structures in 32-bit processes or WoW64 processes
    /// where pointers are 32 bits.
    pub fn __read_string32_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 8];
        vmi.read_in(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        ctx.address = string_buffer as u64;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read_in(ctx, &mut buffer)?;

        Ok(buffer)
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` or
    /// `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` or
    /// `_UNICODE_STRING` structures in 64-bit processes where pointers
    /// are 64 bits.
    pub fn __read_string64_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<Vec<u8>, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 16];
        vmi.read_in(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
            buffer[15],
        ]);

        ctx.address = string_buffer;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read_in(ctx, &mut buffer)?;

        Ok(buffer)
    }

    /// Reads string from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        // `_ANSI_STRING` is unfortunately missing in the PDB symbols.
        // However, its layout is same as `_UNICODE_STRING`.
        match self.offsets._UNICODE_STRING.Buffer.size {
            4 => self.read_ansi_string32_in(vmi, ctx),
            8 => self.read_ansi_string64_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let buffer = self.__read_string32_in(vmi, ctx)?;

        Ok(String::from_utf8_lossy(&buffer).into())
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let buffer = self.__read_string64_in(vmi, ctx)?;

        Ok(String::from_utf8_lossy(&buffer).into())
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        match self.offsets._UNICODE_STRING.Buffer.size {
            4 => self.read_unicode_string32_in(vmi, ctx),
            8 => self.read_unicode_string64_in(vmi, ctx),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let buffer = self.__read_string32_in(vmi, ctx)?;

        Ok(String::from_utf16_lossy(
            &buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ))
    }

    /// Reads string from a 64-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 64-bit processes where pointers are 64 bits.
    pub fn read_unicode_string64_in(
        &self,
        vmi: VmiState<Driver, Self>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let buffer = self.__read_string64_in(vmi, ctx)?;

        Ok(String::from_utf16_lossy(
            &buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ))
    }

    // endregion: String

    // region: User Address

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
    pub fn lowest_user_address(&self, _vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        Ok(Va(0x10000))
    }

    /// Retrieves the highest user-mode address.
    ///
    /// This method reads the highest user-mode address from the Windows kernel.
    /// The value is cached after the first read for performance.
    pub fn highest_user_address(&self, vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        self.highest_user_address
            .get_or_try_init(|| {
                let MmHighestUserAddress =
                    self.kernel_image_base(vmi)? + self.symbols.MmHighestUserAddress;

                vmi.read_va_native(MmHighestUserAddress)
            })
            .copied()
    }

    /// Checks if a given address is a valid user-mode address.
    ///
    /// This method determines whether the provided address falls within
    /// the range of valid user-mode addresses in Windows.
    pub fn is_valid_user_address(
        &self,
        vmi: VmiState<Driver, Self>,
        address: Va,
    ) -> Result<bool, VmiError> {
        let lowest_user_address = self.lowest_user_address(vmi)?;
        let highest_user_address = self.highest_user_address(vmi)?;

        Ok(address >= lowest_user_address && address <= highest_user_address)
    }

    // endregion: User Address

    /// xxx
    pub fn image<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
        image_base: Va,
    ) -> Result<WindowsImage<'a, Driver>, VmiError> {
        Ok(WindowsImage::new(vmi, image_base))
    }

    /// xxx
    pub fn linked_list<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
        list_head: Va,
        offset: u64,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + 'a, VmiError> {
        Ok(ListEntryIterator::new(vmi, list_head, offset))
    }
}

#[allow(non_snake_case)]
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

    fn kernel_image_base(&self, vmi: VmiState<Driver, Self>) -> Result<Va, VmiError> {
        Driver::Architecture::kernel_image_base(vmi, self)
    }

    fn kernel_information_string(&self, vmi: VmiState<Driver, Self>) -> Result<String, VmiError> {
        self.nt_build_lab
            .get_or_try_init(|| {
                let NtBuildLab = self.symbols.NtBuildLab;

                let kernel_image_base = self.kernel_image_base(vmi)?;
                vmi.read_string(kernel_image_base + NtBuildLab)
            })
            .cloned()
    }

    fn kpti_enabled(&self, vmi: VmiState<Driver, Self>) -> Result<bool, VmiError> {
        self.ki_kva_shadow
            .get_or_try_init(|| {
                let KiKvaShadow = self.symbols.KiKvaShadow;

                let KiKvaShadow = match KiKvaShadow {
                    Some(KiKvaShadow) => KiKvaShadow,
                    None => return Ok(false),
                };

                let kernel_image_base = self.kernel_image_base(vmi)?;
                Ok(vmi.read_u8(kernel_image_base + KiKvaShadow)? != 0)
            })
            .copied()
    }

    fn modules<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + 'a, VmiError> {
        let PsLoadedModuleList = self.kernel_image_base(vmi)? + self.symbols.PsLoadedModuleList;
        let KLDR_DATA_TABLE_ENTRY = &self.offsets._KLDR_DATA_TABLE_ENTRY;

        Ok(self
            .linked_list(
                vmi,
                PsLoadedModuleList,
                KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.offset,
            )?
            .map(move |result| result.map(|entry| WindowsModule::new(vmi, entry))))
    }

    fn processes<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + 'a, VmiError> {
        let PsActiveProcessHead = self.kernel_image_base(vmi)? + self.symbols.PsActiveProcessHead;
        let EPROCESS = &self.offsets._EPROCESS;

        Ok(self
            .linked_list(vmi, PsActiveProcessHead, EPROCESS.ActiveProcessLinks.offset)?
            .map(move |result| {
                result.map(|entry| WindowsProcess::new(vmi, ProcessObject(entry)))
            }))
    }

    fn process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'a>, VmiError> {
        Ok(WindowsProcess::new(vmi, process))
    }

    fn current_process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Process<'a>, VmiError> {
        self.current_thread(vmi)?.attached_process()
    }

    fn system_process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Process<'a>, VmiError> {
        let PsInitialSystemProcess =
            self.kernel_image_base(vmi)? + self.symbols.PsInitialSystemProcess;

        let process = vmi.read_va_native(PsInitialSystemProcess)?;
        Ok(WindowsProcess::new(vmi, ProcessObject(process)))
    }

    fn thread<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        thread: ThreadObject,
    ) -> Result<Self::Thread<'a>, VmiError> {
        Ok(WindowsThread::new(vmi, thread))
    }

    fn current_thread<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Thread<'a>, VmiError> {
        let KPCR = &self.offsets._KPCR;
        let KPRCB = &self.offsets._KPRCB;

        let kpcr = self.current_kpcr(vmi);

        if kpcr.is_null() {
            return Err(VmiError::Other("Invalid KPCR"));
        }

        let addr = kpcr + KPCR.Prcb.offset + KPRCB.CurrentThread.offset;
        let result = vmi.read_va_native(addr)?;

        if result.is_null() {
            return Err(VmiError::Other("Invalid thread"));
        }

        Ok(WindowsThread::new(vmi, ThreadObject(result)))
    }

    fn image<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        image_base: Va,
    ) -> Result<Self::Image<'a>, VmiError> {
        Ok(WindowsImage::new(vmi, image_base))
    }

    fn module<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        module: Va,
    ) -> Result<Self::Module<'a>, VmiError> {
        Ok(WindowsModule::new(vmi, module))
    }

    fn region<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        region: Va,
    ) -> Result<Self::Region<'a>, VmiError> {
        Ok(WindowsRegion::new(vmi, region))
    }

    fn syscall_argument(&self, vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(vmi, self, index)
    }

    fn function_argument(&self, vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(vmi, self, index)
    }

    fn function_return_value(&self, vmi: VmiState<Driver, Self>) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(vmi, self)
    }

    fn last_error(&self, vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError> {
        let KTHREAD = &self.offsets._KTHREAD;
        let TEB = &self.offsets._TEB;

        let current_thread = self.current_thread(vmi)?.object()?;
        let teb = vmi.read_va_native(current_thread.0 + KTHREAD.Teb.offset)?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(teb + TEB.LastErrorValue.offset)?;

        Ok(Some(result))
    }
}
