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

use ::object::{
    pe::{
        ImageNtHeaders32, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    },
    read::pe::{optional_header_magic, ExportTarget, ImageNtHeaders},
    LittleEndian as LE,
};
use isr_core::Profile;
use vmi_arch_amd64::{Amd64, Cr3};
use vmi_core::{
    os::{
        OsArchitecture, OsExt, OsImageExportedSymbol, OsMapped, OsModule, OsProcess, OsRegion,
        OsRegionKind, ProcessId, ProcessObject, StructReader, ThreadId, ThreadObject, VmiOs,
    },
    AccessContext, Architecture, Gfn, Hex, MemoryAccess, Pa, Registers as _, Va, VmiCore,
    VmiDriver, VmiError, VmiSession,
};
use vmi_macros::derive_trait_from_impl;
use zerocopy::{FromBytes, IntoBytes};

mod arch;
use self::arch::ArchAdapter;

mod iter;
pub use self::iter::{ListEntryIterator, TreeNodeIterator};

mod pe;
pub use self::pe::{CodeView, PeError, PeLite, PeLite32, PeLite64};

mod offsets;
use self::offsets::{v1, v2};
pub use self::offsets::{Offsets, OffsetsExt, Symbols}; // TODO: make private + remove offsets() & symbols() methods

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

    kernel_image_base: RefCell<Option<Va>>,
    highest_user_address: RefCell<Option<Va>>,
    object_root_directory: RefCell<Option<Va>>, // _OBJECT_DIRECTORY*
    object_header_cookie: RefCell<Option<u8>>,
    object_type_cache: RefCell<HashMap<Va, WindowsObjectType>>,

    ki_kva_shadow: RefCell<Option<bool>>,
    mm_pfn_database: RefCell<Option<Va>>,
    nt_build_lab: RefCell<Option<String>>,
    nt_build_lab_ex: RefCell<Option<String>>,

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

/// Represents a `_HANDLE_TABLE` structure.
#[derive(Debug)]
pub struct WindowsHandleTable {
    /// The `TableCode` field of the handle table.
    ///
    /// A pointer to the top level handle table tree node.
    pub table_code: u64,
}

/// Represents a `_HANDLE_TABLE_ENTRY` structure.
#[derive(Debug)]
pub struct WindowsHandleTableEntry {
    /// The `Object` (or `ObjectPointerBits`) field of the handle table entry.
    ///
    /// A pointer to an `_OBJECT_HEADER` structure.
    pub object: Va, // _OBJECT_HEADER*

    /// The `ObAttributes` (or `Attributes`) field of the handle table entry.
    pub attributes: u32,

    /// The `GrantedAccess` (or `GrantedAccessBits`) field of the handle table entry.
    pub granted_access: u32,
}

/// Represents a `_PEB` structure.
#[derive(Debug)]
pub struct WindowsPeb {
    /// The address of this `_PEB` structure.
    pub address: Va,

    /// The `Peb->ProcessParameters->CurrentDirectory` field.
    pub current_directory: String,

    /// The `Peb->ProcessParameters->DllPath` field.
    pub dll_path: String,

    /// The `Peb->ProcessParameters->ImagePathName` field.
    pub image_path_name: String,

    /// The `Peb->ProcessParameters->CommandLine` field.
    pub command_line: String,
}

/// Identifies the type of a Windows kernel object.
///
/// Windows uses a object-based kernel architecture where various system
/// resources (processes, threads, files, etc.) are represented as kernel
/// objects. This enum identifies the different types of objects that can
/// be encountered during introspection.
///
/// Each variant corresponds to a specific object type string used internally
/// by the Windows kernel. For example, "Process" for process objects,
/// "Thread" for thread objects, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsObjectType {
    /// ALPC Port object.
    ///
    /// Represented by `_ALPC_PORT` structure.
    /// Has `ALPC Port` type name.
    AlpcPort,

    /// Debug object.
    ///
    /// Represented by `_DEBUG_OBJECT` structure.
    /// Has `DebugObject` type name.
    DebugObject,

    /// Device object.
    ///
    /// Represented by `_DEVICE_OBJECT` structure.
    /// Has `Device` type name.
    Device,

    /// Directory object.
    ///
    /// Represented by `_OBJECT_DIRECTORY` structure.
    /// Has `Directory` type name.
    Directory,

    /// Driver object.
    ///
    /// Represented by `_DRIVER_OBJECT` structure.
    /// Has `Driver` type name.
    Driver,

    /// Event object.
    ///
    /// Represented by `_KEVENT` structure.
    /// Has `Event` type name.
    Event,

    /// File object.
    ///
    /// Represented by `_FILE_OBJECT` structure.
    /// Has `File` type name.
    File,

    /// Job object.
    ///
    /// Represented by `_EJOB` structure.
    /// Has `Job` type name.
    Job,

    /// Key object.
    ///
    /// Represented by `_CM_KEY_BODY` structure.
    /// Has `Key` type name.
    Key,

    /// Mutant object.
    ///
    /// Represented by `_KMUTANT` structure.
    /// Has `Mutant` type name.
    Mutant,

    /// Port object.
    ///
    /// Represented by `_PORT_MESSAGE` structure.
    /// Has `Port` type name.
    Port,

    /// Process object.
    ///
    /// Represented by `_EPROCESS` structure.
    /// Has `Process` type name.
    Process,

    /// Section object.
    ///
    /// Represented by `_SECTION` (or `_SECTION_OBJECT`) structure.
    /// Has `Section` type name.
    Section,

    /// Symbolic link object.
    ///
    /// Represented by `_OBJECT_SYMBOLIC_LINK` structure.
    /// Has `SymbolicLink` type name.
    SymbolicLink,

    /// Thread object.
    ///
    /// Represented by `_ETHREAD` structure.
    /// Has `Thread` type name.
    Thread,

    /// Timer object.
    ///
    /// Represented by `_KTIMER` structure.
    /// Has `Timer` type name.
    Timer,

    /// Token object.
    ///
    /// Represented by `_TOKEN` structure.
    /// Has `Token` type name.
    Token,

    /// Type object.
    ///
    /// Represented by `_OBJECT_TYPE` structure.
    /// Has `Type` type name.
    Type,
}

/// A Windows object name.
///
/// Represents the name of a Windows object, along with its directory.
#[derive(Debug)]
pub struct WindowsObjectName {
    /// A `Directory` field of the `_OBJECT_HEADER_NAME_INFO` structure.
    ///
    /// A pointer to the `_OBJECT_DIRECTORY` structure.
    pub directory: Va, // _OBJECT_DIRECTORY*

    /// A `Name` field of the `_OBJECT_HEADER_NAME_INFO` structure.
    pub name: String,
}

/// A Windows object.
#[derive(Debug)]
pub enum WindowsObject {
    /// File object.
    File(WindowsFileObject),

    /// Section object.
    Section(WindowsSectionObject),
}

/// A Windows file object.
#[derive(Debug)]
pub struct WindowsFileObject {
    /// The `DeviceObject` field of the file object.
    ///
    /// A pointer to the `_DEVICE_OBJECT` structure.
    pub device_object: Va,

    /// The `FileName` field of the file object.
    pub filename: String,
}

/// A Windows section object.
#[derive(Debug)]
pub struct WindowsSectionObject {
    /// The virtual address range of the section.
    pub region: OsRegion,

    /// The size of the section.
    pub size: u64,
}

/// Represents a `_VAD` structure.
#[derive(Debug)]
pub struct WindowsVad {
    /// The `StartingVpn` field of the VAD.
    ///
    /// The starting virtual page number of the VAD.
    pub starting_vpn: u64,

    /// The `EndingVpn` field of the VAD.
    ///
    /// The ending virtual page number of the VAD.
    pub ending_vpn: u64,

    /// The `VadType` field of the VAD.
    pub vad_type: u8,

    /// The `Protection` field of the VAD.
    pub protection: u8,

    /// The `PrivateMemory` field of the VAD.
    pub private_memory: bool,

    /// The `MemCommit` field of the VAD.
    pub mem_commit: bool,

    /// The `Left` field of the VAD.
    pub left_child: Va,

    /// The `Right` field of the VAD.
    pub right_child: Va,
}

/// Represents a `KLDR_DATA_TABLE_ENTRY` structure.
#[derive(Debug)]
pub struct WindowsModule {
    /// The `DllBase` field of the module.
    ///
    /// The base address of the module.
    pub base_address: Va,

    /// The `EntryPoint` field of the module.
    ///
    /// The entry point of the module.
    pub entry_point: Va,

    /// The `SizeOfImage` field of the module.
    ///
    /// The size of the module image.
    pub size: u64,

    /// The `FullDllName` field of the module.
    ///
    /// The full name of the module.
    pub full_name: String,

    /// The `BaseDllName` field of the module.
    ///
    /// The base name of the module.
    pub name: String,
}

//
// Private types
//

/// The address space type in a WoW64 process.
enum WindowsWow64Kind {
    /// Native address space.
    Native = 0,

    /// x86 (32-bit) address space under WoW64.
    X86 = 1,
    // Arm32 = 2,
    // Amd64 = 3,
    // ChpeX86 = 4,
    // VsmEnclave = 5,
}

/// A 32-bit or 64-bit virtual address in WoW64 processes.
struct WindowsWow64Va {
    /// The virtual address.
    va: Va,

    /// The kind of the virtual address.
    kind: WindowsWow64Kind,
}

impl WindowsWow64Va {
    fn native(va: Va) -> Self {
        Self {
            va,
            kind: WindowsWow64Kind::Native,
        }
    }

    fn x86(va: Va) -> Self {
        Self {
            va,
            kind: WindowsWow64Kind::X86,
        }
    }
}

#[derive_trait_from_impl(
    os_session_name = WindowsOsSessionExt,
    os_context_name = WindowsOsExt,
    os_session_prober_name = WindowsOsSessionProberExt,
    os_context_prober_name = WindowsOsProberExt
)]
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
            kernel_image_base: RefCell::new(None),
            highest_user_address: RefCell::new(None),
            object_root_directory: RefCell::new(None),
            object_header_cookie: RefCell::new(None),
            object_type_cache: RefCell::new(HashMap::new()),
            ki_kva_shadow: RefCell::new(None),
            mm_pfn_database: RefCell::new(None),
            nt_build_lab: RefCell::new(None),
            nt_build_lab_ex: RefCell::new(None),
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

    #[expect(clippy::only_used_in_recursion)]
    fn enumerate_tree_node_v1(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        node: Va,
        callback: &mut impl FnMut(Va) -> bool,
        offsets: &v1::Offsets,
    ) -> Result<(), VmiError> {
        let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

        let balanced_node = StructReader::new(
            vmi,
            registers.address_context(node),
            MMADDRESS_NODE.effective_len(),
        )?;

        let left = Va(balanced_node.read(MMADDRESS_NODE.LeftChild)?);
        if !left.is_null() {
            self.enumerate_tree_node_v1(vmi, registers, left, callback, offsets)?;
        }

        if !callback(node) {
            return Ok(());
        }

        let right = Va(balanced_node.read(MMADDRESS_NODE.RightChild)?);
        if !right.is_null() {
            self.enumerate_tree_node_v1(vmi, registers, right, callback, offsets)?;
        }

        Ok(())
    }

    #[expect(clippy::only_used_in_recursion)]
    fn enumerate_tree_node_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        node: Va,
        callback: &mut impl FnMut(Va) -> bool,
        offsets: &v2::Offsets,
    ) -> Result<(), VmiError> {
        let RTL_BALANCED_NODE = &offsets._RTL_BALANCED_NODE;

        let balanced_node = StructReader::new(
            vmi,
            registers.address_context(node),
            RTL_BALANCED_NODE.effective_len(),
        )?;

        let left = Va(balanced_node.read(RTL_BALANCED_NODE.Left)?);
        if !left.is_null() {
            self.enumerate_tree_node_v2(vmi, registers, left, callback, offsets)?;
        }

        if !callback(node) {
            return Ok(());
        }

        let right = Va(balanced_node.read(RTL_BALANCED_NODE.Right)?);
        if !right.is_null() {
            self.enumerate_tree_node_v2(vmi, registers, right, callback, offsets)?;
        }

        Ok(())
    }

    fn enumerate_tree_v1(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        root: Va,
        mut callback: impl FnMut(Va) -> bool,
        offsets: &v1::Offsets,
    ) -> Result<(), VmiError> {
        let MM_AVL_TABLE = &offsets._MM_AVL_TABLE;
        let MMADDRESS_NODE = &offsets._MMADDRESS_NODE;

        // NumberGenericTableElements is a ULONG_PTR, which is the same size
        // as a pointer.
        let count = vmi.read_va(
            registers.address_context(root + MM_AVL_TABLE.NumberGenericTableElements.offset),
            registers.address_width(),
        )?;

        let count = MM_AVL_TABLE.NumberGenericTableElements.value_from(count.0);
        if count == 0 {
            return Ok(());
        }

        // Table->BalancedRoot.RightChild
        let root = vmi.read_va(
            registers.address_context(
                root + MM_AVL_TABLE.BalancedRoot.offset + MMADDRESS_NODE.RightChild.offset,
            ),
            registers.address_width(),
        )?;

        self.enumerate_tree_node_v1(vmi, registers, root, &mut callback, offsets)
    }

    fn enumerate_tree_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        root: Va,
        mut callback: impl FnMut(Va) -> bool,
        offsets: &v2::Offsets,
    ) -> Result<(), VmiError> {
        self.enumerate_tree_node_v2(vmi, registers, root, &mut callback, offsets)
    }

    fn image_exported_symbols_generic<Pe>(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<Vec<OsImageExportedSymbol>, VmiError>
    where
        Pe: ImageNtHeaders,
    {
        let mut data = [0u8; Amd64::PAGE_SIZE as usize];
        vmi.read(registers.address_context(image_base), &mut data)?;

        let pe = PeLite::<Pe>::parse(&data).map_err(|err| VmiError::Os(err.into()))?;
        let entry = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        let mut data = vec![0u8; entry.size.get(LE) as usize];
        vmi.read(
            registers.address_context(image_base + entry.virtual_address.get(LE) as u64),
            &mut data,
        )?;

        let exports = pe.exports(&data).map_err(|err| VmiError::Os(err.into()))?;
        Ok(exports
            .iter()
            .filter_map(|export| match export.target {
                ExportTarget::Address(address) => Some(OsImageExportedSymbol {
                    name: String::from_utf8_lossy(export.name?).to_string(),
                    address: image_base + address as u64,
                }),
                _ => None,
            })
            .collect())
    }

    // region: File

    /// Extracts the `FileName` from a `FILE_OBJECT` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// UNICODE_STRING FileName = FileObject->FileName;
    /// return FileName;
    /// ```
    ///
    /// # Notes
    ///
    /// This operation might fail as the filename is allocated from paged pool.
    pub fn file_object_to_filename(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        file_object: Va,
    ) -> Result<String, VmiError> {
        let FILE_OBJECT = &self.offsets.common._FILE_OBJECT;

        // Note that filename is allocated from paged pool,
        // so this read might fail.
        self.read_unicode_string(
            vmi,
            registers.address_context(file_object + FILE_OBJECT.FileName.offset),
        )
    }

    /// Constructs the full path of a file from its `FILE_OBJECT`.
    ///
    /// This function first reads the `DeviceObject` field of the `FILE_OBJECT`
    /// structure. Then it reads the `ObjectNameInfo` of the `DeviceObject`
    /// and its directory. Finally, it concatenates the device directory
    /// name, device name, and file name.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    ///
    /// POBJECT_HEADER_NAME_INFO DeviceNameInfo = ObjectNameInfo(DeviceObject);
    /// POBJECT_HEADER_NAME_INFO DeviceDirectoryNameInfo = DeviceNameInfo->Directory
    ///     ? ObjectNameInfo(DeviceNameInfo->Directory)
    ///     : NULL;
    ///
    /// if (DeviceDirectoryNameInfo->Name != NULL) {
    ///     FullPath += '\\' + DeviceDirectoryNameInfo->Name;
    /// }
    ///
    /// if (DeviceNameInfo->Name != NULL) {
    ///     FullPath += '\\' + DeviceNameInfo->Name;
    /// }
    ///
    /// FullPath += FileObject->FileName;
    ///
    /// return FullPath;
    /// ```
    ///
    /// # Panics
    /// Panics if the provided object is not a file object.
    pub fn file_object_to_full_path(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        file_object: Va,
    ) -> Result<String, VmiError> {
        let file = match self.parse_file_object(vmi, registers, file_object)? {
            WindowsObject::File(file) => file,
            _ => panic!("Not a file object"),
        };

        let device = self.object_name(vmi, registers, file.device_object)?;
        let directory = match &device {
            Some(device) => self.object_name(vmi, registers, device.directory)?,
            None => None,
        };

        let mut result = String::new();
        if let Some(directory) = directory {
            result.push('\\');
            result.push_str(&directory.name);
        }

        if let Some(device) = device {
            result.push('\\');
            result.push_str(&device.name);
        }

        result.push_str(&file.filename);

        Ok(result)
    }

    /// Extracts the filename from a `CONTROL_AREA` structure.
    ///
    /// This function first reads the `FilePointer` field of the `CONTROL_AREA`
    /// structure, then reads the `FileName` field of the `FILE_OBJECT`
    /// structure pointed by the `FilePointer`.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PFILE_OBJECT FileObject = ControlArea->FilePointer;
    /// UNICODE_STRING FileName = FileObject->FileName;
    /// return FileName;
    /// ```
    pub fn control_area_to_filename(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        control_area: Va,
    ) -> Result<String, VmiError> {
        let EX_FAST_REF = &self.offsets.common._EX_FAST_REF;
        let CONTROL_AREA = &self.offsets.common._CONTROL_AREA;

        let file_pointer = vmi.read_va(
            registers.address_context(control_area + CONTROL_AREA.FilePointer.offset),
            registers.address_width(),
        )?;

        // The file pointer is in fact an `_EX_FAST_REF` structure,
        // where the low bits are used to store the reference count.
        debug_assert_eq!(EX_FAST_REF.RefCnt.offset, 0);
        debug_assert_eq!(EX_FAST_REF.RefCnt.bit_position, 0);
        let file_pointer = file_pointer & !((1 << EX_FAST_REF.RefCnt.bit_length) - 1);
        //let file_pointer = file_pointer & !0xf;

        self.file_object_to_filename(vmi, registers, file_pointer)
    }

    // endregion: File

    // region: Handle

    /// Checks if the given handle is a kernel handle.
    pub fn is_kernel_handle(
        &self,
        _vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        handle: u64,
    ) -> Result<bool, VmiError> {
        const KERNEL_HANDLE_MASK32: u64 = 0x8000_0000;
        const KERNEL_HANDLE_MASK64: u64 = 0xffff_ffff_8000_0000;

        match registers.effective_address_width() {
            4 => Ok(handle & KERNEL_HANDLE_MASK32 == KERNEL_HANDLE_MASK32),
            8 => Ok(handle & KERNEL_HANDLE_MASK64 == KERNEL_HANDLE_MASK64),
            _ => panic!("Unsupported address width"),
        }
    }

    /// Retrieves the handle table for a given process.
    pub fn handle_table(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<WindowsHandleTable, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;
        let HANDLE_TABLE = &self.offsets.common._HANDLE_TABLE;

        let handle_table = vmi.read_va(
            registers.address_context(process.0 + EPROCESS.ObjectTable.offset),
            registers.address_width(),
        )?;

        let table_code = vmi.read_address(
            registers.address_context(handle_table + HANDLE_TABLE.TableCode.offset),
            registers.address_width(),
        )?;

        Ok(WindowsHandleTable { table_code })
    }

    /// Looks up a specific handle table entry for a given process and handle.
    pub fn handle_table_entry(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        handle: u64,
    ) -> Result<Option<WindowsHandleTableEntry>, VmiError> {
        let mut process = process;
        let mut handle = handle;

        if self.is_kernel_handle(vmi, registers, handle)? {
            process = self.system_process(vmi, registers)?;
            handle &= 0x7fff_ffff;
        }

        let handle_table = self.handle_table(vmi, registers, process)?;
        let entry_address =
            self.handle_table_entry_lookup(vmi, registers, &handle_table, handle)?;
        self.parse_handle_table_entry(vmi, registers, entry_address)
    }

    /// Performs a lookup in the handle table to find the address of a handle
    /// table entry.
    ///
    /// Implements the multi-level handle table lookup algorithm used by
    /// Windows. Returns the virtual address of the handle table entry.
    pub fn handle_table_entry_lookup(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        handle_table: &WindowsHandleTable,
        handle: u64,
    ) -> Result<Va, VmiError> {
        const SIZEOF_POINTER: u64 = 8;
        const SIZEOF_HANDLE_TABLE_ENTRY: u64 = 16;

        const LOWLEVEL_COUNT: u64 = 256; // (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
        const MIDLEVEL_COUNT: u64 = 512; // (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

        const LEVEL_CODE_MASK: u64 = 3;
        const HANDLE_VALUE_INC: u64 = 4;

        let level = handle_table.table_code & LEVEL_CODE_MASK;
        let table = Va(handle_table.table_code - level);

        //
        // The 2 least significant bits of a handle are available to the
        // application and are ignored by the system.
        //

        let mut index = handle & !0b11;

        match level {
            0 => Ok(table + index * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC)),

            1 => {
                let table2 = table;
                let i = index % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                index -= i;
                let j = index / (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                let table1 = vmi.read_va(
                    registers.address_context(table2 + j * SIZEOF_POINTER),
                    registers.address_width(),
                )?;

                Ok(table1 + i * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC))
            }

            2 => {
                let table3 = table;
                let i = index % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                index -= i;
                let mut k = index / (LOWLEVEL_COUNT * HANDLE_VALUE_INC);

                let j = k % MIDLEVEL_COUNT;
                k -= j;
                k /= MIDLEVEL_COUNT;

                let table2 = vmi.read_va(
                    registers.address_context(table3 + k * SIZEOF_POINTER),
                    registers.address_width(),
                )?;
                let table1 = vmi.read_va(
                    registers.address_context(table2 + j * SIZEOF_POINTER),
                    registers.address_width(),
                )?;

                Ok(table1 + i * (SIZEOF_HANDLE_TABLE_ENTRY / HANDLE_VALUE_INC))
            }

            _ => unreachable!(),
        }
    }

    /// Converts a handle to the virtual address of the corresponding object.
    ///
    /// Uses the handle table entry lookup to find the object address for a
    /// given handle.
    pub fn handle_to_object_address(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        handle: u64,
    ) -> Result<Option<Va>, VmiError> {
        Ok(self
            .handle_table_entry(vmi, registers, process, handle)?
            .map(|entry| entry.object))
    }

    /// Retrieves the WindowsObject corresponding to a given handle in a
    /// process.
    pub fn handle_to_object(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        handle: u64,
    ) -> Result<Option<WindowsObject>, VmiError> {
        match self.handle_to_object_address(vmi, registers, process, handle)? {
            Some(object) => self.object_from_address(vmi, registers, object),
            None => Ok(None),
        }
    }

    fn parse_handle_table_entry(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        entry: Va,
    ) -> Result<Option<WindowsHandleTableEntry>, VmiError> {
        match &self.offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                self.parse_handle_table_entry_v1(vmi, registers, entry, offsets)
            }
            Some(OffsetsExt::V2(offsets)) => {
                self.parse_handle_table_entry_v2(vmi, registers, entry, offsets)
            }
            None => panic!("OffsetsExt not set"),
        }
    }

    fn parse_handle_table_entry_v1(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        entry: Va,
        offsets: &v1::Offsets,
    ) -> Result<Option<WindowsHandleTableEntry>, VmiError> {
        const OBJ_PROTECT_CLOSE: u64 = 0x00000001;
        const OBJ_INHERIT: u64 = 0x00000002;
        const OBJ_AUDIT_OBJECT_CLOSE: u64 = 0x00000004;
        const OBJ_HANDLE_ATTRIBUTES: u64 = OBJ_PROTECT_CLOSE | OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE;

        let HANDLE_TABLE_ENTRY = &offsets._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &self.offsets.common._OBJECT_HEADER;

        let handle_table_entry = StructReader::new(
            vmi,
            registers.address_context(entry),
            HANDLE_TABLE_ENTRY.effective_len(),
        )?;
        let object = handle_table_entry.read(HANDLE_TABLE_ENTRY.Object)?;
        let attributes = handle_table_entry.read(HANDLE_TABLE_ENTRY.ObAttributes)?;
        let granted_access = handle_table_entry.read(HANDLE_TABLE_ENTRY.GrantedAccess)? as u32;

        let object = Va(object & !OBJ_HANDLE_ATTRIBUTES);
        let object = object + OBJECT_HEADER.Body.offset;

        let attributes = (attributes & OBJ_HANDLE_ATTRIBUTES) as u32;

        Ok(Some(WindowsHandleTableEntry {
            object,
            attributes,
            granted_access,
        }))
    }

    fn parse_handle_table_entry_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        entry: Va,
        offsets: &v2::Offsets,
    ) -> Result<Option<WindowsHandleTableEntry>, VmiError> {
        let HANDLE_TABLE_ENTRY = &offsets._HANDLE_TABLE_ENTRY;
        let OBJECT_HEADER = &self.offsets.common._OBJECT_HEADER;

        #[repr(C)]
        #[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
        #[allow(non_camel_case_types, non_snake_case)]
        struct _HANDLE_TABLE_ENTRY {
            LowValue: u64,
            HighValue: u64,
        }

        // Fetch the handle table entry
        let handle_table_entry =
            vmi.read_struct::<_HANDLE_TABLE_ENTRY>(registers.address_context(entry))?;

        // Parse the handle table entry
        let object_pointer_bits = HANDLE_TABLE_ENTRY
            .ObjectPointerBits
            .value_from(handle_table_entry.LowValue);

        let attributes = HANDLE_TABLE_ENTRY
            .Attributes
            .value_from(handle_table_entry.LowValue) as u32;

        let granted_access = HANDLE_TABLE_ENTRY
            .GrantedAccessBits
            .value_from(handle_table_entry.HighValue) as u32;

        let object = Va(0xffff_0000_0000_0000 | object_pointer_bits << 4);
        let object = object + OBJECT_HEADER.Body.offset;

        Ok(Some(WindowsHandleTableEntry {
            object,
            attributes,
            granted_access,
        }))
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
        vmi: &VmiCore<Driver>,
        registers: &<<Driver as VmiDriver>::Architecture as Architecture>::Registers,
    ) -> Result<Option<String>, VmiError> {
        let NtBuildLabEx = match self.symbols.NtBuildLabEx {
            Some(offset) => offset,
            None => return Ok(None),
        };

        if let Some(nt_build_lab_ex) = self.nt_build_lab_ex.borrow().as_ref() {
            return Ok(Some(nt_build_lab_ex.clone()));
        }

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let nt_build_lab_ex =
            vmi.read_string(registers.address_context(kernel_image_base + NtBuildLabEx))?;
        *self.nt_build_lab_ex.borrow_mut() = Some(nt_build_lab_ex.clone());

        Ok(Some(nt_build_lab_ex))
    }

    /// Retrieves information about a kernel module from a pointer to
    /// `KLDR_DATA_TABLE_ENTRY`
    pub fn kernel_module(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        addr: Va, // _KLDR_DATA_TABLE_ENTRY*
    ) -> Result<OsModule, VmiError> {
        let KLDR_DATA_TABLE_ENTRY = &self.offsets.common._KLDR_DATA_TABLE_ENTRY;

        let base_address = vmi.read_va(
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.DllBase.offset),
            registers.address_width(),
        )?;

        let size = vmi
            .read_u32(registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.SizeOfImage.offset))?
            as u64;

        let name = self.read_unicode_string(
            vmi,
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.BaseDllName.offset),
        )?;

        Ok(OsModule {
            base_address,
            size,
            name,
        })
    }

    // endregion: Kernel

    // region: Memory

    /// Retrieves information about a Virtual Address Descriptor (VAD) for a
    /// given address.
    ///
    /// This method extracts details such as the starting and ending virtual
    /// page numbers, VAD type, memory protection, and other flags
    /// associated with the specified VAD.
    pub fn vad(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        vad: Va,
    ) -> Result<WindowsVad, VmiError> {
        let MMVAD_FLAGS = &self.offsets.common._MMVAD_FLAGS;
        let MMVAD_SHORT = &self.offsets.common._MMVAD_SHORT;

        let mmvad = StructReader::new(
            vmi,
            registers.address_context(vad),
            MMVAD_SHORT.effective_len(),
        )?;
        let starting_vpn_low = mmvad.read(MMVAD_SHORT.StartingVpn)?;
        let ending_vpn_low = mmvad.read(MMVAD_SHORT.EndingVpn)?;
        let starting_vpn_high = match MMVAD_SHORT.StartingVpnHigh {
            Some(StartingVpnHigh) => mmvad.read(StartingVpnHigh)?,
            None => 0,
        };
        let ending_vpn_high = match MMVAD_SHORT.EndingVpnHigh {
            Some(EndingVpnHigh) => mmvad.read(EndingVpnHigh)?,
            None => 0,
        };

        let starting_vpn = (starting_vpn_high << 32) | starting_vpn_low;
        let ending_vpn = (ending_vpn_high << 32) | ending_vpn_low;

        let vad_flags = mmvad.read(MMVAD_SHORT.VadFlags)?;
        let vad_type = MMVAD_FLAGS.VadType.value_from(vad_flags) as u8;
        let protection = MMVAD_FLAGS.Protection.value_from(vad_flags) as u8;
        let private_memory = MMVAD_FLAGS.PrivateMemory.value_from(vad_flags) != 0;

        // If `MMVAD_FLAGS.MemCommit` is present (Windows 7), then we fetch the
        // value from it. Otherwise, we load the `VadFlags1` field from the VAD
        // and fetch it from there.
        let mem_commit = match MMVAD_FLAGS.MemCommit {
            // `MemCommit` is present in `MMVAD_FLAGS`
            Some(MemCommit) => MemCommit.value_from(vad_flags) != 0,

            None => match (&self.offsets.ext, MMVAD_SHORT.VadFlags1) {
                // `MemCommit` is present in `MMVAD_FLAGS1`
                (Some(OffsetsExt::V2(offsets)), Some(VadFlags1)) => {
                    let MMVAD_FLAGS1 = &offsets._MMVAD_FLAGS1;
                    let vad_flags1 = mmvad.read(VadFlags1)?;
                    MMVAD_FLAGS1.MemCommit.value_from(vad_flags1) != 0
                }
                _ => {
                    panic!("Failed to read MemCommit from VAD");
                }
            },
        };

        let left_child = Va(mmvad.read(MMVAD_SHORT.Left)?);
        let right_child = Va(mmvad.read(MMVAD_SHORT.Right)?);

        Ok(WindowsVad {
            starting_vpn,
            ending_vpn,
            vad_type,
            protection,
            private_memory,
            mem_commit,
            left_child,
            right_child,
        })
    }

    /// Locates the `VadRoot` for a given process. Returns the address of the
    /// root node.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// // For Windows 7:
    /// return Process->VadRoot->BalancedRoot;
    ///
    /// // For Windows 8.1 and later:
    /// return Process->VadRoot->Root;
    /// ```
    pub fn vad_root(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        match &self.offsets.ext {
            Some(OffsetsExt::V1(offsets)) => self.vad_root_v1(vmi, registers, process, offsets),
            Some(OffsetsExt::V2(offsets)) => self.vad_root_v2(vmi, registers, process, offsets),
            None => panic!("OffsetsExt not set"),
        }
    }

    fn vad_root_v1(
        &self,
        _vmi: &VmiCore<Driver>,
        _registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        offsets: &v1::Offsets,
    ) -> Result<Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;
        let MM_AVL_TABLE = &offsets._MM_AVL_TABLE;

        // The `_MM_AVL_TABLE::BalancedRoot` field is of `_MMADDRESS_NODE` type,
        // which represents the root.
        let vad_root = process.0 + EPROCESS.VadRoot.offset + MM_AVL_TABLE.BalancedRoot.offset;

        Ok(vad_root)
    }

    fn vad_root_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        offsets: &v2::Offsets,
    ) -> Result<Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;
        let RTL_AVL_TREE = &offsets._RTL_AVL_TREE;

        // The `RTL_AVL_TREE::Root` field is of pointer type (`_RTL_BALANCED_NODE*`),
        // thus we need to dereference it to get the actual node.
        let vad_root = vmi.read_va(
            registers
                .address_context(process.0 + EPROCESS.VadRoot.offset + RTL_AVL_TREE.Root.offset),
            registers.address_width(),
        )?;

        Ok(vad_root)
    }

    /// Retrieves the `VadHint` for a given process. Returns the address of the
    /// hint node in the VAD tree.
    ///
    /// The VAD hint is an optimization used by Windows to speed up VAD lookups.
    /// This method returns the address of the hint node in the VAD tree.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// // For Windows 7:
    /// return Process->VadRoot->NodeHint;
    ///
    /// // For Windows 8.1 and later:
    /// return Process->VadRoot->Hint;
    /// ```
    pub fn vad_hint(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        match &self.offsets.ext {
            Some(OffsetsExt::V1(offsets)) => self.vad_hint_v1(vmi, registers, process, offsets),
            Some(OffsetsExt::V2(offsets)) => self.vad_hint_v2(vmi, registers, process, offsets),
            None => panic!("OffsetsExt not set"),
        }
    }

    fn vad_hint_v1(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        offsets: &v1::Offsets,
    ) -> Result<Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;
        let MM_AVL_TABLE = &offsets._MM_AVL_TABLE;

        let vad_hint = vmi.read_va(
            registers.address_context(
                process.0 + EPROCESS.VadRoot.offset + MM_AVL_TABLE.NodeHint.offset,
            ),
            registers.address_width(),
        )?;

        Ok(vad_hint)
    }

    fn vad_hint_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        _offsets: &v2::Offsets,
    ) -> Result<Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        let VadHint = EPROCESS
            .VadHint
            .expect("VadHint is not present in common offsets");

        let vad_hint = vmi.read_va(
            registers.address_context(process.0 + VadHint.offset),
            registers.address_width(),
        )?;

        Ok(vad_hint)
    }

    /// Converts a VAD (Virtual Address Descriptor) to an [`OsRegion`] structure.
    ///
    /// This method extracts information from a VAD and creates an `OsRegion`
    /// object, which includes details about the memory region's address range,
    /// protection, and mapping type.
    pub fn vad_to_region(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        vad: Va,
    ) -> Result<OsRegion, VmiError> {
        let MMVAD = &self.offsets.common._MMVAD;
        let SUBSECTION = &self.offsets.common._SUBSECTION;

        let mmvad = self.vad(vmi, registers, vad)?;
        let start = Va(mmvad.starting_vpn << 12);
        let end = Va((mmvad.ending_vpn + 1) << 12);

        const MM_ZERO_ACCESS: u8 = 0; // this value is not used.
        const MM_READONLY: u8 = 1;
        const MM_EXECUTE: u8 = 2;
        const MM_EXECUTE_READ: u8 = 3;
        const MM_READWRITE: u8 = 4; // bit 2 is set if this is writable.
        const MM_WRITECOPY: u8 = 5;
        const MM_EXECUTE_READWRITE: u8 = 6;
        const MM_EXECUTE_WRITECOPY: u8 = 7;

        let protection = match mmvad.protection {
            MM_ZERO_ACCESS => MemoryAccess::default(),
            MM_READONLY => MemoryAccess::R,
            MM_EXECUTE => MemoryAccess::X,
            MM_EXECUTE_READ => MemoryAccess::RX,
            MM_READWRITE => MemoryAccess::RW,
            MM_WRITECOPY => MemoryAccess::RW, // REVIEW: is this correct?
            MM_EXECUTE_READWRITE => MemoryAccess::RWX,
            MM_EXECUTE_WRITECOPY => MemoryAccess::RWX, // REVIEW: is this correct?
            _ => MemoryAccess::default(),
        };

        const VadImageMap: u8 = 2;

        if mmvad.vad_type != VadImageMap {
            return Ok(OsRegion {
                start,
                end,
                protection,
                kind: OsRegionKind::Private,
            });
        }

        let subsection = vmi.read_va(
            registers.address_context(vad + MMVAD.Subsection.offset),
            registers.address_width(),
        )?;

        let control_area = vmi.read_va(
            registers.address_context(subsection + SUBSECTION.ControlArea.offset),
            registers.address_width(),
        )?;

        // Note that filename is allocated from paged pool,
        // so this read might fail.
        let path = self.control_area_to_filename(vmi, registers, control_area);

        Ok(OsRegion {
            start,
            end,
            protection,
            kind: OsRegionKind::Mapped(OsMapped {
                path: path.map(Some),
            }),
        })
    }

    /// Retrieves all memory regions associated with a process's VAD tree.
    ///
    /// This method traverses the entire VAD tree of a process and converts
    /// each VAD into an [`OsRegion`], providing a comprehensive view of the
    /// process's virtual address space.
    pub fn vad_root_to_regions(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        vad_root: Va,
    ) -> Result<Vec<OsRegion>, VmiError> {
        let mut result = Vec::new();

        self.enumerate_tree(vmi, registers, vad_root, |vad| {
            match self.vad_to_region(vmi, registers, vad) {
                Ok(region) => result.push(region),
                Err(err) => tracing::warn!(?err, ?vad, "Failed to convert VAD to region"),
            }

            true
        })?;

        Ok(result)
    }

    /// Locates the VAD that encompasses a specific virtual address in a process.
    ///
    /// This method efficiently searches the VAD tree to find the VAD node that
    /// corresponds to the given virtual address within the process's address
    /// space. Its functionality is similar to the Windows kernel's internal
    /// `MiLocateAddress()` function.
    ///
    /// Returns virtual address of the matching VAD if found, or `None` if the
    /// address is not within any VAD.
    ///
    pub fn find_process_vad(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<Va>, VmiError> {
        let mut vad_va = self.vad_hint(vmi, registers, process)?;

        if vad_va.is_null() {
            return Ok(None);
        }

        let vpn = address.0 >> 12;

        let vad = self.vad(vmi, registers, vad_va)?;
        if vpn >= vad.starting_vpn && vpn <= vad.ending_vpn {
            return Ok(Some(vad_va));
        }

        vad_va = self.vad_root(vmi, registers, process)?;

        while !vad_va.is_null() {
            let vad = self.vad(vmi, registers, vad_va)?;

            if vpn < vad.starting_vpn {
                vad_va = vad.left_child;
            }
            else if vpn > vad.ending_vpn {
                vad_va = vad.right_child;
            }
            else {
                return Ok(Some(vad_va));
            }
        }

        Ok(None)
    }

    /// Retrieves the virtual address of the Page Frame Number (PFN) database.
    ///
    /// The PFN database is a critical data structure in Windows memory management,
    /// containing information about each physical page in the system.
    ///
    /// # Implementation Details
    ///
    /// The PFN database is located by reading the `MmPfnDatabase` symbol from
    /// the kernel image.
    fn pfn_database(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError> {
        let MmPfnDatabase = self.symbols.MmPfnDatabase;

        if let Some(mm_pfn_database) = self.mm_pfn_database.borrow().as_ref() {
            return Ok(*mm_pfn_database);
        }

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let mm_pfn_database = vmi.read_va(
            registers.address_context(kernel_image_base + MmPfnDatabase),
            registers.address_width(),
        )?;
        *self.mm_pfn_database.borrow_mut() = Some(mm_pfn_database);
        Ok(mm_pfn_database)
    }

    fn modify_pfn_reference_count(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        pfn: Gfn,
        increment: i16,
    ) -> Result<Option<u16>, VmiError> {
        let MMPFN = &self.offsets.common._MMPFN;

        // const ZeroedPageList: u16 = 0;
        // const FreePageList: u16 = 1;
        const StandbyPageList: u16 = 2; //this list and before make up available pages.
        const ModifiedPageList: u16 = 3;
        const ModifiedNoWritePageList: u16 = 4;
        // const BadPageList: u16 = 5;
        const ActiveAndValid: u16 = 6;
        // const TransitionPage: u16 = 7;

        let pfn = self.pfn_database(vmi, registers)? + u64::from(pfn) * MMPFN.len() as u64;

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

        let pfn_value =
            vmi.read_u32(registers.address_context(pfn + MMPFN.ReferenceCount.offset))?;
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

        vmi.write_u16(
            registers.address_context(pfn + MMPFN.ReferenceCount.offset),
            new_ref_count,
        )?;

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
    /// os.lock_pfn(vmi, registers, pfn)?;
    /// // The VM will automatically resume when `_guard` goes out of scope
    /// # Ok(())
    /// # }
    /// ```
    pub fn lock_pfn(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        pfn: Gfn,
    ) -> Result<Option<u16>, VmiError> {
        self.modify_pfn_reference_count(vmi, registers, pfn, 1)
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
    /// os.unlock_pfn(vmi, registers, pfn)?;
    /// // The VM will automatically resume when `_guard` goes out of scope
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock_pfn(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        pfn: Gfn,
    ) -> Result<Option<u16>, VmiError> {
        self.modify_pfn_reference_count(vmi, registers, pfn, -1)
    }

    // endregion: Memory

    // region: Misc

    /// Retrieves the virtual address of the current Kernel Processor Control
    /// Region (KPCR).
    ///
    /// The KPCR is a per-processor data structure in Windows that contains
    /// critical information about the current processor state. This method
    /// returns the virtual address of the KPCR for the current processor.
    pub fn current_kpcr(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Va {
        Driver::Architecture::current_kpcr(self, vmi, registers)
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
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
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

        let record = vmi.read_struct::<_EXCEPTION_RECORD>(registers.address_context(address))?;

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
    pub fn last_status(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u32>, VmiError> {
        let KTHREAD = &self.offsets.common._KTHREAD;
        let TEB = &self.offsets.common._TEB;

        let current_thread = self.current_thread(vmi, registers)?;
        let teb = vmi.read_va(
            registers.address_context(current_thread.0 + KTHREAD.Teb.offset),
            registers.address_width(),
        )?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(registers.address_context(teb + TEB.LastStatusValue.offset))?;
        Ok(Some(result))
    }

    // endregion: Misc

    // region: Object

    /// Retrieves the name of a Windows kernel object.
    pub fn object_lookup(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        directory: Va,
        needle: impl AsRef<str>,
    ) -> Result<Option<Va>, VmiError> {
        let OBJECT_DIRECTORY = &self.offsets.common._OBJECT_DIRECTORY;
        let OBJECT_DIRECTORY_ENTRY = &self.offsets.common._OBJECT_DIRECTORY_ENTRY;

        let object_type = self.object_type(vmi, registers, directory)?;
        assert_eq!(object_type, Some(WindowsObjectType::Directory));

        let needle = needle.as_ref();

        for i in 0..37 {
            println!("i: {}", i);

            let hash_bucket = vmi.read_va(
                registers.address_context(directory + OBJECT_DIRECTORY.HashBuckets.offset + i * 8),
                registers.address_width(),
            )?;

            let mut entry = hash_bucket;
            while !entry.is_null() {
                println!("  entry: {}", entry);

                let object = vmi.read_va(
                    registers.address_context(entry + OBJECT_DIRECTORY_ENTRY.Object.offset),
                    registers.address_width(),
                )?;
                println!("    object: {}", object);

                let hash_value = vmi.read_u32(
                    registers.address_context(entry + OBJECT_DIRECTORY_ENTRY.HashValue.offset),
                )?;
                println!("    hash_value: {}", hash_value);

                if let Some(name) = self.object_name(vmi, registers, object)? {
                    println!("    name: {}", name.name);

                    if name.name == needle {
                        return Ok(Some(object));
                    }
                }

                entry = vmi.read_va(
                    registers.address_context(entry + OBJECT_DIRECTORY_ENTRY.ChainLink.offset),
                    registers.address_width(),
                )?;
            }
        }

        return Ok(None);
    }

    /// Retrieves the root directory object for the Windows kernel.
    ///
    /// # Implementation Details
    ///
    /// The root directory object is located by reading the `ObpRootDirectoryObject`
    /// symbol from the kernel image.
    pub fn object_root_directory(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError> {
        if let Some(object_root_directory) = *self.object_root_directory.borrow() {
            return Ok(object_root_directory);
        }

        let ObpRootDirectoryObject =
            self.kernel_image_base(vmi, registers)? + self.symbols.ObpRootDirectoryObject;

        let object_root_directory = vmi.read_va(
            registers.address_context(ObpRootDirectoryObject),
            registers.address_width(),
        )?;
        *self.object_root_directory.borrow_mut() = Some(object_root_directory);
        Ok(object_root_directory)
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
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u8>, VmiError> {
        if let Some(cookie) = *self.object_header_cookie.borrow() {
            return Ok(Some(cookie));
        }

        let ObHeaderCookie = match self.symbols.ObHeaderCookie {
            Some(cookie) => cookie,
            None => return Ok(None),
        };

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let cookie = vmi.read_u8(registers.address_context(kernel_image_base + ObHeaderCookie))?;
        *self.object_header_cookie.borrow_mut() = Some(cookie);
        Ok(Some(cookie))
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
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
    ) -> Result<Option<WindowsObjectType>, VmiError> {
        let ObTypeIndexTable = self.symbols.ObTypeIndexTable;
        let OBJECT_HEADER = &self.offsets.common._OBJECT_HEADER;

        let object_header = object - OBJECT_HEADER.Body.offset;
        let type_index =
            vmi.read_u8(registers.address_context(object_header + OBJECT_HEADER.TypeIndex.offset))?;

        let index = match self.object_header_cookie(vmi, registers)? {
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

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let object_type = vmi.read_va(
            registers.address_context(
                kernel_image_base + ObTypeIndexTable + index * 8, // REVIEW: replace 8 with registers.address_width()?
            ),
            registers.address_width(),
        )?;

        if let Some(typ) = self.object_type_cache.borrow().get(&object_type) {
            return Ok(Some(*typ));
        }

        let object_name = self.read_unicode_string(
            vmi,
            registers.address_context(object_type + self.offsets.common._OBJECT_TYPE.Name.offset),
        )?;

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

    /// Retrieves the name of a named kernel object.
    ///
    /// Many Windows kernel objects (like mutexes, events, etc.) can have names.
    /// This method extracts the name of such an object, if present. It also
    /// provides information about the object's containing directory in the
    /// object namespace.
    ///
    /// Returns `None` if the object does not have a `OBJECT_HEADER_NAME_INFO`.
    pub fn object_name(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
    ) -> Result<Option<WindowsObjectName>, VmiError> {
        let ObpInfoMaskToOffset = self.symbols.ObpInfoMaskToOffset;
        let OBJECT_HEADER = &self.offsets.common._OBJECT_HEADER;
        let OBJECT_HEADER_NAME_INFO = &self.offsets.common._OBJECT_HEADER_NAME_INFO;

        let object_header = object - OBJECT_HEADER.Body.offset;
        let info_mask =
            vmi.read_u8(registers.address_context(object_header + OBJECT_HEADER.InfoMask.offset))?;

        bitflags::bitflags! {
            struct InfoFlags: u8 {
                const CREATOR_INFO = 0x01;
                const NAME_INFO = 0x02;
                const HANDLE_INFO = 0x04;
                const QUOTA_INFO = 0x08;
                const PROCESS_INFO = 0x10;
            }
        }

        let info_flags = InfoFlags::from_bits_truncate(info_mask);
        if !info_flags.contains(InfoFlags::NAME_INFO) {
            return Ok(None);
        }

        // Offset = ObpInfoMaskToOffset[OBJECT_HEADER->InfoMask & (DesiredHeaderBit | (DesiredHeaderBit-1))]

        let mask = info_mask & (InfoFlags::NAME_INFO.bits() | (InfoFlags::NAME_INFO.bits() - 1));
        let mask = mask as u64;

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let offset = vmi
            .read_u8(registers.address_context(kernel_image_base + ObpInfoMaskToOffset + mask))?
            as u64;

        let object_header_name_info = object_header - offset;

        let directory = vmi.read_va(
            registers.address_context(
                object_header_name_info + OBJECT_HEADER_NAME_INFO.Directory.offset,
            ),
            registers.address_width(),
        )?;

        let name = self.read_unicode_string(
            vmi,
            registers
                .address_context(object_header_name_info + OBJECT_HEADER_NAME_INFO.Name.offset),
        )?;

        Ok(Some(WindowsObjectName { directory, name }))
    }

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
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        object_attributes: Va,
    ) -> Result<Option<String>, VmiError> {
        let OBJECT_ATTRIBUTES = &self.offsets.common._OBJECT_ATTRIBUTES;

        let object_name_address = vmi.read_va(
            registers.address_context(object_attributes + OBJECT_ATTRIBUTES.ObjectName.offset),
            registers.address_width(),
        )?;

        if object_name_address.is_null() {
            return Ok(None);
        }

        let object_name =
            self.read_unicode_string(vmi, registers.address_context(object_name_address))?;

        let root_directory = vmi.read_va(
            registers.address_context(object_attributes + OBJECT_ATTRIBUTES.RootDirectory.offset),
            registers.address_width(),
        )?;

        if root_directory.is_null() {
            return Ok(Some(object_name));
        }

        let object =
            match self.handle_to_object(vmi, registers, process, u64::from(root_directory))? {
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

    /// Parses a Windows object from its memory address.
    ///
    /// Determines the object type and calls the appropriate parsing method.
    /// Currently supports File and Section object types.
    pub fn object_from_address(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
    ) -> Result<Option<WindowsObject>, VmiError> {
        match self.object_type(vmi, registers, object)? {
            Some(WindowsObjectType::File) => {
                Ok(Some(self.parse_file_object(vmi, registers, object)?))
            }
            Some(WindowsObjectType::Section) => self.parse_section_object(vmi, registers, object),
            _ => Ok(None),
        }
    }

    /// Parses a `FILE_OBJECT` structure.
    ///
    /// Extracts the device object and filename from the `FILE_OBJECT`.
    /// Returns a [`WindowsObject::File`] variant.
    fn parse_file_object(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
    ) -> Result<WindowsObject, VmiError> {
        let FILE_OBJECT = &self.offsets.common._FILE_OBJECT;

        let device_object = vmi.read_va(
            registers.address_context(object + FILE_OBJECT.DeviceObject.offset),
            registers.address_width(),
        )?;

        let filename = self.file_object_to_filename(vmi, registers, object)?;
        Ok(WindowsObject::File(WindowsFileObject {
            device_object,
            filename,
        }))
    }

    /// Parses a Windows section object.
    ///
    /// Delegates to version-specific parsing methods based on the available
    /// offsets. Currently supports `SECTION_OBJECT` and `SECTION` structures.
    /// Returns a [`WindowsObject::Section`] variant.
    fn parse_section_object(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
    ) -> Result<Option<WindowsObject>, VmiError> {
        match &self.offsets.ext {
            Some(OffsetsExt::V1(offsets)) => Ok(Some(
                self.parse_section_object_v1(vmi, registers, object, offsets)?,
            )),
            Some(OffsetsExt::V2(offsets)) => Ok(Some(
                self.parse_section_object_v2(vmi, registers, object, offsets)?,
            )),
            None => panic!("OffsetsExt not set"),
        }
    }

    fn parse_section_object_v1(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
        offsets: &v1::Offsets,
    ) -> Result<WindowsObject, VmiError> {
        let SECTION_OBJECT = &offsets._SECTION_OBJECT;
        let SEGMENT_OBJECT = &offsets._SEGMENT_OBJECT;
        let MMSECTION_FLAGS = &self.offsets.common._MMSECTION_FLAGS;

        let section = StructReader::new(
            vmi,
            registers.address_context(object),
            SECTION_OBJECT.effective_len(),
        )?;
        let starting_vpn = section.read(SECTION_OBJECT.StartingVa)?;
        let ending_vpn = section.read(SECTION_OBJECT.EndingVa)?;
        let segment = section.read(SECTION_OBJECT.Segment)?;

        let segment = StructReader::new(
            vmi,
            registers.address_context(segment.into()),
            SEGMENT_OBJECT.effective_len(),
        )?;
        let size = segment.read(SEGMENT_OBJECT.SizeOfSegment)?;
        let flags = segment.read(SEGMENT_OBJECT.MmSectionFlags)?;
        let flags = vmi.read_u32(registers.address_context(flags.into()))? as u64;

        let file = MMSECTION_FLAGS.File.value_from(flags) != 0;
        let _image = MMSECTION_FLAGS.Image.value_from(flags) != 0;

        let kind = if file {
            let control_area = vmi.read_va(
                registers.address_context(object + SEGMENT_OBJECT.ControlArea.offset),
                registers.address_width(),
            )?;

            let path = self.control_area_to_filename(vmi, registers, control_area);

            OsRegionKind::Mapped(OsMapped {
                path: path.map(Some),
            })
        }
        else {
            OsRegionKind::Private
        };

        Ok(WindowsObject::Section(WindowsSectionObject {
            region: OsRegion {
                start: Va(starting_vpn << 12),
                end: Va((ending_vpn + 1) << 12),
                protection: MemoryAccess::default(),
                kind,
            },
            size,
        }))
    }

    fn parse_section_object_v2(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        object: Va,
        offsets: &v2::Offsets,
    ) -> Result<WindowsObject, VmiError> {
        let SECTION = &offsets._SECTION;
        let MMSECTION_FLAGS = &self.offsets.common._MMSECTION_FLAGS;

        let section = StructReader::new(
            vmi,
            registers.address_context(object),
            SECTION.effective_len(),
        )?;
        let starting_vpn = section.read(SECTION.StartingVpn)?;
        let ending_vpn = section.read(SECTION.EndingVpn)?;
        let size = section.read(SECTION.SizeOfSection)?;
        let flags = section.read(SECTION.Flags)?;

        let file = MMSECTION_FLAGS.File.value_from(flags) != 0;
        let _image = MMSECTION_FLAGS.Image.value_from(flags) != 0;

        //
        // We have to distinguish between FileObject and ControlArea.
        // Here's an excerpt from _SECTION:
        //
        //     union {
        //       union {
        //         PCONTROL_AREA ControlArea;
        //         PFILE_OBJECT FileObject;
        //         struct {
        //           ULONG_PTR RemoteImageFileObject : 1;
        //           ULONG_PTR RemoteDataFileObject : 1;
        //         };
        //       };
        //     };
        //
        // Based on information from Geoff Chappell's website, we can determine whether
        // ControlArea is in fact FileObject by checking the lowest 2 bits of the
        // pointer.
        //
        // ref: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/mi/section.htm
        //

        let kind = if file {
            let control_area = vmi.read_va(
                registers.address_context(object + SECTION.ControlArea.offset),
                registers.address_width(),
            )?;

            let path = if u64::from(control_area) & 0x3 != 0 {
                let file_object = control_area;
                self.file_object_to_filename(vmi, registers, file_object)
            }
            else {
                self.control_area_to_filename(vmi, registers, control_area)
            };

            OsRegionKind::Mapped(OsMapped {
                path: path.map(Some),
            })
        }
        else {
            OsRegionKind::Private
        };

        Ok(WindowsObject::Section(WindowsSectionObject {
            region: OsRegion {
                start: Va(starting_vpn << 12),
                end: Va((ending_vpn + 1) << 12),
                protection: MemoryAccess::default(),
                kind,
            },
            size,
        }))
    }

    // endregion: Object

    // region: PEB

    /// Retrieves the Process Environment Block (PEB) for a given process.
    ///
    /// The PEB contains crucial information about a process, including its
    /// loaded modules, environment variables, and command line arguments.
    pub fn process_peb(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<WindowsPeb, VmiError> {
        let root = self.process_translation_root(vmi, registers, process)?;

        let address = self.__process_peb_address(vmi, registers, process, root)?;
        let current_directory = self.__process_current_directory(vmi, registers, process, root)?;
        let dll_path = self.__process_dll_path(vmi, registers, process, root)?;
        let image_path_name = self.__process_image_path_name(vmi, registers, process, root)?;
        let command_line = self.__process_command_line(vmi, registers, process, root)?;

        Ok(WindowsPeb {
            address: address.va,
            current_directory,
            dll_path,
            image_path_name,
            command_line,
        })
    }

    /// Internal method to get the address of the PEB.
    ///
    /// This method handles both native (non-WoW64) processes and WoW64
    /// processes, returning the appropriate PEB address based on the
    /// process architecture.
    fn __process_peb_address(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<WindowsWow64Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        let wow64 = vmi.read_va(
            (process.0 + EPROCESS.WoW64Process.offset, root),
            registers.address_width(),
        )?;

        if wow64.is_null() {
            let peb64 = vmi.read_va(
                (process.0 + EPROCESS.Peb.offset, root),
                registers.address_width(),
            )?;

            Ok(WindowsWow64Va::native(peb64))
        }
        else {
            let peb32 = match &self.offsets.ext {
                Some(OffsetsExt::V1(_)) => wow64,
                Some(OffsetsExt::V2(v2)) => vmi.read_va(
                    (wow64 + v2._EWOW64PROCESS.Peb.offset, root),
                    registers.address_width(),
                )?,
                None => panic!("OffsetsExt not set"),
            };

            Ok(WindowsWow64Va::x86(peb32))
        }
    }

    /// Internal method to retrieve the address of
    /// `RTL_USER_PROCESS_PARAMETERS`.
    ///
    /// This structure contains various process-specific parameters, including
    /// the command line, current directory, and DLL search path.
    fn __process_rtl_process_parameters(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<WindowsWow64Va, VmiError> {
        let address = self.__process_peb_address(vmi, registers, process, root)?;

        match address.kind {
            WindowsWow64Kind::Native => {
                let PEB = &self.offsets.common._PEB;

                let va = vmi.read_va(
                    (address.va + PEB.ProcessParameters.offset, root),
                    registers.address_width(),
                )?;

                Ok(WindowsWow64Va::native(va))
            }
            WindowsWow64Kind::X86 => {
                const PEB32_ProcessParameters_offset: u64 = 0x10;

                let va = vmi.read_va(
                    (address.va + PEB32_ProcessParameters_offset, root),
                    registers.address_width(),
                )?;

                Ok(WindowsWow64Va::x86(va))
            }
        }
    }

    /// Gets the current working directory of a process.
    ///
    /// This method retrieves the full path of the current working directory
    /// for the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING CurrentDirectory = ProcessParameters->CurrentDirectory;
    /// return CurrentDirectory;
    /// ```
    pub fn process_current_directory(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let root = self.process_translation_root(vmi, registers, process)?;
        self.__process_current_directory(vmi, registers, process, root)
    }

    /// Internal method to get the current directory, handling both 32-bit and
    /// 64-bit processes.
    fn __process_current_directory(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<String, VmiError> {
        let address = self.__process_rtl_process_parameters(vmi, registers, process, root)?;

        match address.kind {
            WindowsWow64Kind::Native => {
                self.process_current_directory_native(vmi, root, address.va)
            }
            WindowsWow64Kind::X86 => self.process_current_directory_32bit(vmi, root, address.va),
        }
    }

    /// Retrieves the current directory for a native (non-WoW64) process.
    fn process_current_directory_native(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        let CURDIR = &self.offsets.common._CURDIR;
        let RTL_USER_PROCESS_PARAMETERS = &self.offsets.common._RTL_USER_PROCESS_PARAMETERS;

        self.read_unicode_string(
            vmi,
            (
                rtl_process_parameters
                    + RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.offset
                    + CURDIR.DosPath.offset,
                root,
            ),
        )
    }

    /// Retrieves the current directory for a 32-bit process running under
    /// WoW64.
    fn process_current_directory_32bit(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset: u64 = 0x24;

        self.read_unicode_string32(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS32_CurrentDirectory_offset,
                root,
            ),
        )
    }

    /// Gets the DLL search path for a process.
    ///
    /// This method retrieves the list of directories that the system searches
    /// when loading DLLs for the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING DllPath = ProcessParameters->DllPath;
    /// return DllPath;
    /// ```
    pub fn process_dll_path(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let root = self.process_translation_root(vmi, registers, process)?;
        self.__process_dll_path(vmi, registers, process, root)
    }

    /// Internal method to get the DLL path, handling both 32-bit and 64-bit
    /// processes.
    fn __process_dll_path(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<String, VmiError> {
        let address = self.__process_rtl_process_parameters(vmi, registers, process, root)?;

        match address.kind {
            WindowsWow64Kind::Native => self.process_dll_path_native(vmi, root, address.va),
            WindowsWow64Kind::X86 => self.process_dll_path_32bit(vmi, root, address.va),
        }
    }

    /// Retrieves the DLL search path for a native (non-WoW64) process.
    fn process_dll_path_native(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        let RTL_USER_PROCESS_PARAMETERS = &self.offsets.common._RTL_USER_PROCESS_PARAMETERS;

        self.read_unicode_string(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS.DllPath.offset,
                root,
            ),
        )
    }

    /// Retrieves the DLL search path for a 32-bit process running under WoW64.
    fn process_dll_path_32bit(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_DllPath_offset: u64 = 0x30;

        self.read_unicode_string32(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS32_DllPath_offset,
                root,
            ),
        )
    }

    /// Gets the full path of the executable image for a process.
    ///
    /// This method retrieves the full file system path of the main executable
    /// that was used to create the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING ImagePathName = ProcessParameters->ImagePathName;
    /// return ImagePathName;
    /// ```
    pub fn process_image_path_name(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let root = self.process_translation_root(vmi, registers, process)?;
        self.__process_image_path_name(vmi, registers, process, root)
    }

    /// Internal method to get the image path name, handling both 32-bit and
    /// 64-bit processes.
    fn __process_image_path_name(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<String, VmiError> {
        let address = self.__process_rtl_process_parameters(vmi, registers, process, root)?;

        match address.kind {
            WindowsWow64Kind::Native => self.process_image_path_name_native(vmi, root, address.va),
            WindowsWow64Kind::X86 => self.process_image_path_name_32bit(vmi, root, address.va),
        }
    }

    /// Retrieves the image path name for a native (non-WoW64) process.
    fn process_image_path_name_native(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        let RTL_USER_PROCESS_PARAMETERS = &self.offsets.common._RTL_USER_PROCESS_PARAMETERS;

        self.read_unicode_string(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS.ImagePathName.offset,
                root,
            ),
        )
    }

    /// Retrieves the image path name for a 32-bit process running under WoW64.
    fn process_image_path_name_32bit(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset: u64 = 0x38;

        self.read_unicode_string32(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS32_ImagePathName_offset,
                root,
            ),
        )
    }

    /// Gets the command line used to launch a process.
    ///
    /// This method retrieves the full command line string, including the
    /// executable path and any arguments, used to start the specified process.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NtCurrentPeb()->ProcessParameters;
    /// PUNICODE_STRING CommandLine = ProcessParameters->CommandLine;
    /// return CommandLine;
    /// ```
    pub fn process_command_line(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let root = self.process_translation_root(vmi, registers, process)?;
        self.__process_command_line(vmi, registers, process, root)
    }

    /// Internal method to get the command line, handling both 32-bit and 64-bit
    /// processes.
    fn __process_command_line(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        root: Pa,
    ) -> Result<String, VmiError> {
        let address = self.__process_rtl_process_parameters(vmi, registers, process, root)?;

        match address.kind {
            WindowsWow64Kind::Native => self.process_command_line_native(vmi, root, address.va),
            WindowsWow64Kind::X86 => self.process_command_line_32bit(vmi, root, address.va),
        }
    }

    /// Retrieves the command line for a native (non-WoW64) process.
    fn process_command_line_native(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        let RTL_USER_PROCESS_PARAMETERS = &self.offsets.common._RTL_USER_PROCESS_PARAMETERS;

        self.read_unicode_string(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS.CommandLine.offset,
                root,
            ),
        )
    }

    /// Retrieves the command line for a 32-bit process running under WoW64.
    fn process_command_line_32bit(
        &self,
        vmi: &VmiCore<Driver>,
        root: Pa,
        rtl_process_parameters: Va,
    ) -> Result<String, VmiError> {
        const RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset: u64 = 0x40;

        self.read_unicode_string32(
            vmi,
            (
                rtl_process_parameters + RTL_USER_PROCESS_PARAMETERS32_CommandLine_offset,
                root,
            ),
        )
    }

    // endregion: PEB

    // region: Process

    /// Extracts the `EPROCESS` structure from a `KTHREAD` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return Thread->Process;
    /// ```
    pub fn process_from_thread(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        thread: ThreadObject,
    ) -> Result<ProcessObject, VmiError> {
        let KTHREAD = &self.offsets.common._KTHREAD;

        let process = vmi.read_va(
            registers.address_context(thread.0 + KTHREAD.Process.offset),
            registers.address_width(),
        )?;

        Ok(ProcessObject(process))
    }

    /// Extracts the `EPROCESS` structure from a `KAPC_STATE` structure.
    ///
    /// # Equivalent C pseudo-code
    ///
    /// ```c
    /// return Thread->ApcState->Process;
    /// ```
    pub fn process_from_thread_apc_state(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        thread: ThreadObject,
    ) -> Result<ProcessObject, VmiError> {
        let KTHREAD = &self.offsets.common._KTHREAD;
        let KAPC_STATE = &self.offsets.common._KAPC_STATE;

        let process = vmi.read_va(
            registers
                .address_context(thread.0 + KTHREAD.ApcState.offset + KAPC_STATE.Process.offset),
            registers.address_width(),
        )?;

        Ok(ProcessObject(process))
    }

    /// Constructs an [`OsProcess`] from an `_EPROCESS`.
    pub fn process_object_to_process(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<OsProcess, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;
        let KPROCESS = &self.offsets.common._KPROCESS;

        let id =
            vmi.read_u32(registers.address_context(process.0 + EPROCESS.UniqueProcessId.offset))?;

        let name =
            vmi.read_string(registers.address_context(process.0 + EPROCESS.ImageFileName.offset))?;

        let translation_root = vmi.read_address(
            registers.address_context(process.0 + KPROCESS.DirectoryTableBase.offset),
            registers.address_width(),
        )?;

        Ok(OsProcess {
            id: id.into(),
            object: process,
            name,
            translation_root: translation_root.into(),
        })
    }

    // endregion: Process

    // region: String

    /// Reads string from an `_ANSI_STRING` structure.
    ///
    /// This method reads a native `_ANSI_STRING` structure which contains
    /// an ASCII/ANSI string. The structure is read according to the current
    /// OS's architecture (32-bit or 64-bit).
    pub fn read_ansi_string(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        //
        // `_ANSI_STRING` is unfortunately missing in the PDB symbols.
        // However, its layout is same as `_UNICODE_STRING`.
        //

        let ANSI_STRING = &self.offsets.common._UNICODE_STRING;

        let string = StructReader::new(vmi, ctx, ANSI_STRING.effective_len())?;
        let string_length = string.read(ANSI_STRING.Length)?;
        let string_buffer = string.read(ANSI_STRING.Buffer)?;

        ctx.address = string_buffer;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read(ctx, &mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).into())
    }

    /// Reads string from a 32-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_ansi_string32(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 8];
        vmi.read(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        ctx.address = string_buffer as u64;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read(ctx, &mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).into())
    }

    /// Reads string from a 64-bit version of `_ANSI_STRING` structure.
    ///
    /// This method is specifically for reading `_ANSI_STRING` structures in
    /// 64-bit processes where pointers are 64 bits.
    pub fn read_ansi_string64(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 16];
        vmi.read(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
            buffer[15],
        ]);

        ctx.address = string_buffer;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read(ctx, &mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).into())
    }

    /// Reads string from a `_UNICODE_STRING` structure.
    ///
    /// This method reads a native `_UNICODE_STRING` structure which contains
    /// a UTF-16 string. The structure is read according to the current OS's
    /// architecture (32-bit or 64-bit).
    pub fn read_unicode_string(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        let UNICODE_STRING = &self.offsets.common._UNICODE_STRING;

        let string = StructReader::new(vmi, ctx, UNICODE_STRING.effective_len())?;
        let string_length = string.read(UNICODE_STRING.Length)?;
        let string_buffer = string.read(UNICODE_STRING.Buffer)?;

        ctx.address = string_buffer;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read(ctx, &mut buffer)?;

        Ok(String::from_utf16_lossy(
            &buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ))
    }

    /// Reads string from a 32-bit version of `_UNICODE_STRING` structure.
    ///
    /// This method is specifically for reading `_UNICODE_STRING` structures
    /// in 32-bit processes or WoW64 processes where pointers are 32 bits.
    pub fn read_unicode_string32(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 8];
        vmi.read(ctx, &mut buffer)?;

        let string_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let string_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let string_buffer = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        ctx.address = string_buffer as u64;

        let mut buffer = vec![0u8; string_length as usize];
        vmi.read(ctx, &mut buffer)?;

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
    pub fn read_unicode_string64(
        &self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AccessContext>,
    ) -> Result<String, VmiError> {
        let mut ctx = ctx.into();

        let mut buffer = [0u8; 16];
        vmi.read(ctx, &mut buffer)?;

        let us_length = u16::from_le_bytes([buffer[0], buffer[1]]);
        // let us_maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
        let us_buffer = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
            buffer[15],
        ]);

        ctx.address = us_buffer;

        let mut buffer = vec![0u8; us_length as usize];
        vmi.read(ctx, &mut buffer)?;

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
    pub fn lowest_user_address(
        &self,
        _vmi: &VmiCore<Driver>,
        _registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError> {
        Ok(Va(0x10000))
    }

    /// Retrieves the highest user-mode address.
    ///
    /// This method reads the highest user-mode address from the Windows kernel.
    /// The value is cached after the first read for performance.
    pub fn highest_user_address(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError> {
        if let Some(highest_user_address) = *self.highest_user_address.borrow() {
            return Ok(highest_user_address);
        }

        let MmHighestUserAddress =
            self.kernel_image_base(vmi, registers)? + self.symbols.MmHighestUserAddress;

        let highest_user_address = vmi.read_va(
            registers.address_context(MmHighestUserAddress),
            registers.address_width(),
        )?;
        *self.highest_user_address.borrow_mut() = Some(highest_user_address);
        Ok(highest_user_address)
    }

    /// Checks if a given address is a valid user-mode address.
    ///
    /// This method determines whether the provided address falls within
    /// the range of valid user-mode addresses in Windows.
    pub fn is_valid_user_address(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        address: Va,
    ) -> Result<bool, VmiError> {
        let lowest_user_address = self.lowest_user_address(vmi, registers)?;
        let highest_user_address = self.highest_user_address(vmi, registers)?;

        Ok(address >= lowest_user_address && address <= highest_user_address)
    }

    // endregion: User Address

    /// xxx
    pub fn linked_list<'a>(
        &'a self,
        vmi: &'a VmiCore<Driver>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        list_head: Va,
        offset: u64,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + 'a, VmiError> {
        Ok(ListEntryIterator::new(
            VmiSession::new(vmi, self),
            registers,
            list_head,
            offset,
        ))
    }

    /// xxx
    pub fn vad_iter<'a>(
        &'a self,
        vmi: &'a VmiCore<Driver>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<impl Iterator<Item = Result<Va, VmiError>> + 'a, VmiError> {
        let root = self.vad_root(vmi, registers, process)?;

        Ok(TreeNodeIterator::new(
            VmiSession::new(vmi, self),
            registers,
            root,
        )?)
    }

    /// Returns the process object iterator.
    pub fn process_iter<'a>(
        &'a self,
        vmi: &'a VmiCore<Driver>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> Result<impl Iterator<Item = Result<OsProcess, VmiError>> + 'a, VmiError> {
        let PsActiveProcessHead =
            self.kernel_image_base(vmi, registers)? + self.symbols.PsActiveProcessHead;

        let EPROCESS = &self.offsets.common._EPROCESS;

        Ok(self
            .linked_list(
                vmi,
                registers,
                PsActiveProcessHead,
                EPROCESS.ActiveProcessLinks.offset,
            )?
            .map(|result| {
                result.and_then(|entry| {
                    self.process_object_to_process(vmi, registers, ProcessObject(entry))
                })
            }))
    }

    /// associated with the specified VAD.
    pub fn module(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        addr: Va,
    ) -> Result<WindowsModule, VmiError> {
        let KLDR_DATA_TABLE_ENTRY = &self.offsets.common._KLDR_DATA_TABLE_ENTRY;

        let base_address = vmi.read_va(
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.DllBase.offset),
            registers.address_width(),
        )?;
        let entry_point = vmi.read_va(
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.EntryPoint.offset),
            registers.address_width(),
        )?;
        let size = vmi
            .read_u32(registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.SizeOfImage.offset))?
            as u64;
        let full_name = self.read_unicode_string(
            vmi,
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.FullDllName.offset),
        )?;
        let name = self.read_unicode_string(
            vmi,
            registers.address_context(addr + KLDR_DATA_TABLE_ENTRY.BaseDllName.offset),
        )?;

        Ok(WindowsModule {
            base_address,
            entry_point,
            size,
            full_name,
            name,
        })
    }

    /// Returns the process object iterator.
    pub fn module_iter<'a>(
        &'a self,
        vmi: &'a VmiCore<Driver>,
        registers: &'a <Driver::Architecture as Architecture>::Registers,
    ) -> Result<impl Iterator<Item = Result<WindowsModule, VmiError>> + 'a, VmiError> {
        let PsLoadedModuleList =
            self.kernel_image_base(vmi, registers)? + self.symbols.PsLoadedModuleList;

        let KLDR_DATA_TABLE_ENTRY = &self.offsets.common._KLDR_DATA_TABLE_ENTRY;

        Ok(self
            .linked_list(
                vmi,
                registers,
                PsLoadedModuleList,
                KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.offset,
            )?
            .map(|result| result.and_then(|entry| self.module(vmi, registers, entry))))
    }
}

#[allow(non_snake_case)]
impl<Driver> VmiOs<Driver> for WindowsOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn kernel_image_base(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError> {
        Driver::Architecture::kernel_image_base(self, vmi, registers)
    }

    fn kernel_information_string(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<<Driver as VmiDriver>::Architecture as Architecture>::Registers,
    ) -> Result<String, VmiError> {
        let NtBuildLab = self.symbols.NtBuildLab;

        if let Some(nt_build_lab) = self.nt_build_lab.borrow().as_ref() {
            return Ok(nt_build_lab.clone());
        }

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let nt_build_lab =
            vmi.read_string(registers.address_context(kernel_image_base + NtBuildLab))?;
        *self.nt_build_lab.borrow_mut() = Some(nt_build_lab.clone());
        Ok(nt_build_lab)
    }

    fn kpti_enabled(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<<Driver as VmiDriver>::Architecture as Architecture>::Registers,
    ) -> Result<bool, VmiError> {
        let KiKvaShadow = self.symbols.KiKvaShadow;

        if let Some(ki_kva_shadow) = self.ki_kva_shadow.borrow().as_ref() {
            return Ok(*ki_kva_shadow);
        }

        let KiKvaShadow = match KiKvaShadow {
            Some(KiKvaShadow) => KiKvaShadow,
            None => {
                *self.ki_kva_shadow.borrow_mut() = Some(false);
                return Ok(false);
            }
        };

        let kernel_image_base = self.kernel_image_base(vmi, registers)?;
        let ki_kva_shadow =
            vmi.read_u8(registers.address_context(kernel_image_base + KiKvaShadow))? != 0;
        *self.ki_kva_shadow.borrow_mut() = Some(ki_kva_shadow);
        Ok(ki_kva_shadow)
    }

    fn modules(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<<Driver as VmiDriver>::Architecture as Architecture>::Registers,
    ) -> Result<Vec<OsModule>, VmiError> {
        let mut result = Vec::new();

        let PsLoadedModuleList =
            self.kernel_image_base(vmi, registers)? + self.symbols.PsLoadedModuleList;

        let KLDR_DATA_TABLE_ENTRY = &self.offsets.common._KLDR_DATA_TABLE_ENTRY;

        self.enumerate_list(vmi, registers, PsLoadedModuleList, |entry| {
            let module_entry = entry - KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.offset;

            if let Ok(module) = self.kernel_module(vmi, registers, module_entry) {
                result.push(module)
            }

            true
        })?;

        Ok(result)
    }

    fn system_process(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<<Driver as VmiDriver>::Architecture as Architecture>::Registers,
    ) -> Result<ProcessObject, VmiError> {
        let PsInitialSystemProcess =
            self.kernel_image_base(vmi, registers)? + self.symbols.PsInitialSystemProcess;

        let process = vmi.read_va(
            registers.address_context(PsInitialSystemProcess),
            registers.address_width(),
        )?;

        Ok(ProcessObject(process))
    }

    fn thread_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        thread: ThreadObject,
    ) -> Result<ThreadId, VmiError> {
        let ETHREAD = &self.offsets.common._ETHREAD;
        let CLIENT_ID = &self.offsets.common._CLIENT_ID;

        let result = vmi.read_u32(
            registers
                .address_context(thread.0 + ETHREAD.Cid.offset + CLIENT_ID.UniqueThread.offset),
        )?;

        Ok(ThreadId(result))
    }

    fn process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        let result =
            vmi.read_u32(registers.address_context(process.0 + EPROCESS.UniqueProcessId.offset))?;

        Ok(ProcessId(result))
    }

    fn current_thread(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ThreadObject, VmiError> {
        let KPCR = &self.offsets.common._KPCR;
        let KPRCB = &self.offsets.common._KPRCB;

        let kpcr = self.current_kpcr(vmi, registers);

        if kpcr.is_null() {
            return Err(VmiError::Other("Invalid KPCR"));
        }

        let addr = kpcr + KPCR.Prcb.offset + KPRCB.CurrentThread.offset;
        let result = vmi.read_va(registers.address_context(addr), registers.address_width())?;

        Ok(ThreadObject(result))
    }

    fn current_thread_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ThreadId, VmiError> {
        let thread = self.current_thread(vmi, registers)?;

        if thread.is_null() {
            return Err(VmiError::Other("Invalid thread"));
        }

        self.thread_id(vmi, registers, thread)
    }

    fn current_process(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ProcessObject, VmiError> {
        let thread = self.current_thread(vmi, registers)?;

        if thread.is_null() {
            return Err(VmiError::Other("Invalid thread"));
        }

        self.process_from_thread_apc_state(vmi, registers, thread)
    }

    fn current_process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ProcessId, VmiError> {
        let process = self.current_process(vmi, registers)?;

        if process.is_null() {
            return Err(VmiError::Other("Invalid process"));
        }

        self.process_id(vmi, registers, process)
    }

    fn processes(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Vec<OsProcess>, VmiError> {
        let mut result = Vec::new();

        let PsActiveProcessHead =
            self.kernel_image_base(vmi, registers)? + self.symbols.PsActiveProcessHead;
        let EPROCESS = &self.offsets.common._EPROCESS;

        self.enumerate_list(vmi, registers, PsActiveProcessHead, |entry| {
            let process_object = entry - EPROCESS.ActiveProcessLinks.offset;

            if let Ok(process) =
                self.process_object_to_process(vmi, registers, process_object.into())
            {
                result.push(process)
            }

            true
        })?;

        Ok(result)
    }

    fn process_parent_process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        let result = vmi.read_u32(
            registers.address_context(process.0 + EPROCESS.InheritedFromUniqueProcessId.offset),
        )?;

        Ok(ProcessId(result))
    }

    fn process_architecture(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<OsArchitecture, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        let wow64process = vmi.read_va(
            registers.address_context(process.0 + EPROCESS.WoW64Process.offset),
            registers.address_width(),
        )?;

        if wow64process.is_null() {
            Ok(OsArchitecture::Amd64)
        }
        else {
            Ok(OsArchitecture::X86)
        }
    }

    fn process_translation_root(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Pa, VmiError> {
        let KPROCESS = &self.offsets.common._KPROCESS;

        let current_process = self.current_process(vmi, registers)?;

        if process == current_process {
            return Ok(registers.translation_root(process.0));
        }

        let root = Cr3::from(u64::from(vmi.read_va(
            registers.address_context(process.0 + KPROCESS.DirectoryTableBase.offset),
            registers.address_width(),
        )?));

        Ok(Pa::from(root))
    }

    fn process_user_translation_root(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Pa, VmiError> {
        let KPROCESS = &self.offsets.common._KPROCESS;
        let UserDirectoryTableBase = match &KPROCESS.UserDirectoryTableBase {
            Some(UserDirectoryTableBase) => UserDirectoryTableBase,
            None => return self.process_translation_root(vmi, registers, process),
        };

        let root = u64::from(vmi.read_va(
            registers.address_context(process.0 + UserDirectoryTableBase.offset),
            registers.address_width(),
        )?);

        if root < Driver::Architecture::PAGE_SIZE {
            return self.process_translation_root(vmi, registers, process);
        }

        Ok(Pa::from(Cr3::from(root)))
    }

    fn process_filename(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        vmi.read_string(registers.address_context(process.0 + EPROCESS.ImageFileName.offset))
    }

    fn process_image_base(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Va, VmiError> {
        let EPROCESS = &self.offsets.common._EPROCESS;

        vmi.read_va(
            registers.address_context(process.0 + EPROCESS.SectionBaseAddress.offset),
            registers.address_width(),
        )
    }

    fn process_regions(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Vec<OsRegion>, VmiError> {
        let vad_root = self.vad_root(vmi, registers, process)?;
        self.vad_root_to_regions(vmi, registers, vad_root)
    }

    fn process_address_is_valid(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError> {
        Driver::Architecture::process_address_is_valid(self, vmi, registers, process, address)
    }

    fn find_process_region(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<OsRegion>, VmiError> {
        let vad = match self.find_process_vad(vmi, registers, process, address)? {
            Some(vad) => vad,
            None => return Ok(None),
        };

        Ok(Some(self.vad_to_region(vmi, registers, vad)?))
    }

    fn image_architecture(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<OsArchitecture, VmiError> {
        let mut data = [0u8; Amd64::PAGE_SIZE as usize];
        vmi.read(registers.address_context(image_base), &mut data)?;

        let pe_magic = optional_header_magic(data.as_ref())
            .map_err(|_| VmiError::Os(PeError::InvalidPeMagic.into()))?;

        match pe_magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Ok(OsArchitecture::X86),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Ok(OsArchitecture::Amd64),
            _ => Ok(OsArchitecture::Unknown),
        }
    }

    fn image_exported_symbols(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<Vec<OsImageExportedSymbol>, VmiError> {
        match self.image_architecture(vmi, registers, image_base)? {
            OsArchitecture::Unknown => Err(VmiError::Os(PeError::InvalidPeMagic.into())),
            OsArchitecture::X86 => {
                tracing::trace!(?image_base, "32-bit PE");
                self.image_exported_symbols_generic::<ImageNtHeaders32>(vmi, registers, image_base)
            }
            OsArchitecture::Amd64 => {
                tracing::trace!(?image_base, "64-bit PE");
                self.image_exported_symbols_generic::<ImageNtHeaders64>(vmi, registers, image_base)
            }
        }
    }

    fn syscall_argument(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError> {
        Driver::Architecture::syscall_argument(self, vmi, registers, index)
    }

    fn function_argument(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError> {
        Driver::Architecture::function_argument(self, vmi, registers, index)
    }

    fn function_return_value(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError> {
        Driver::Architecture::function_return_value(self, vmi, registers)
    }

    fn last_error(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u32>, VmiError> {
        let KTHREAD = &self.offsets.common._KTHREAD;
        let TEB = &self.offsets.common._TEB;

        let current_thread = self.current_thread(vmi, registers)?;
        let teb = vmi.read_va(
            registers.address_context(current_thread.0 + KTHREAD.Teb.offset),
            registers.address_width(),
        )?;

        if teb.is_null() {
            return Ok(None);
        }

        let result = vmi.read_u32(registers.address_context(teb + TEB.LastErrorValue.offset))?;

        Ok(Some(result))
    }
}

impl<Driver> OsExt<Driver> for WindowsOs<Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn enumerate_list(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        list_head: Va,
        mut callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        let mut entry = vmi.read_va(
            registers.address_context(list_head),
            registers.address_width(),
        )?;

        while entry != list_head {
            if !callback(entry) {
                break;
            }

            entry = vmi.read_va(registers.address_context(entry), registers.address_width())?;
        }

        Ok(())
    }

    fn enumerate_tree(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        root: Va,
        callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError> {
        match &self.offsets.ext {
            Some(OffsetsExt::V1(offsets)) => {
                self.enumerate_tree_v1(vmi, registers, root, callback, offsets)
            }
            Some(OffsetsExt::V2(offsets)) => {
                self.enumerate_tree_v2(vmi, registers, root, callback, offsets)
            }
            None => panic!("OffsetsExt not set"),
        }
    }
}
