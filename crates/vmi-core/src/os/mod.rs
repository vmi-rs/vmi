#![doc = include_str!("../../docs/os.md")]

mod common;
mod struct_reader;

use vmi_macros::derive_os_wrapper;

pub use self::{
    common::{
        OsArchitecture, OsImageExportedSymbol, OsMapped, OsModule, OsProcess, OsRegion,
        OsRegionKind, ProcessId, ProcessObject, ThreadId, ThreadObject,
    },
    struct_reader::StructReader,
};
use crate::{
    Architecture, Pa, Va, VmiCore, VmiDriver, VmiError, VmiOsContext, VmiOsContextProber,
    VmiOsSession, VmiOsSessionProber,
};

/// Operating system trait.
#[derive_os_wrapper(
    os_session_name = VmiOsSession,
    os_context_name = VmiOsContext,
    os_session_prober_name = VmiOsSessionProber,
    os_context_prober_name = VmiOsContextProber
)]
pub trait VmiOs<Driver>
where
    Driver: VmiDriver,
{
    /// Retrieves the base address of the kernel image.
    ///
    /// The kernel image base address is usually found using some special
    /// CPU register - for example, a register that contains the address of
    /// the system call handler. Such register is set by the operating system
    /// during boot and is left unchanged (unless some rootkits are involved).
    ///
    /// Therefore, this function can accept the CPU registers from any point
    /// of the VM execution (except for the early boot stage).
    ///
    /// For catching the exact moment when the kernel image base address is
    /// set, you can monitor the `MSR_LSTAR` register (on AMD64) for writes.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: The kernel image base address is usually found using the
    ///   `MSR_LSTAR` register.
    ///
    /// # Notes
    ///
    /// A malicious code (such as a rootkit) could modify values of the
    /// registers, so the returned value might not be accurate.
    fn kernel_image_base(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError>;

    /// Retrieves an implementation-specific string containing kernel
    /// information.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `NtBuildLab` string from the kernel image.
    /// - **Linux**: Retrieves the `linux_banner` string from the kernel image.
    fn kernel_information_string(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<String, VmiError>;

    /// Checks if Kernel Page Table Isolation (KPTI) is enabled.
    fn kpti_enabled(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<bool, VmiError>;

    /// Retrieves a list of loaded kernel modules.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves information from the `PsLoadedModuleList`.
    /// - **Linux**: Retrieves information from the `modules` list.
    fn modules(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Vec<OsModule>, VmiError>;

    /// Retrieves the system process object.
    ///
    /// The system process is the first process created by the kernel.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `PsInitialSystemProcess` global variable.
    /// - **Linux**: Retrieves the `init_task` global variable.
    fn system_process(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ProcessObject, VmiError>;

    /// Retrieves the thread ID for a given thread object.
    fn thread_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        thread: ThreadObject,
    ) -> Result<ThreadId, VmiError>;

    /// Retrieves the process ID for a given process object.
    fn process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError>;

    /// Retrieves the current thread object.
    fn current_thread(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ThreadObject, VmiError>;

    /// Retrieves the current thread ID.
    fn current_thread_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ThreadId, VmiError>;

    /// Retrieves the current process object.
    fn current_process(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ProcessObject, VmiError>;

    /// Retrieves the current process ID.
    fn current_process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<ProcessId, VmiError>;

    /// Retrieves a list of all processes in the system.
    fn processes(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Vec<OsProcess>, VmiError>;

    /// Retrieves the parent process ID for a given process object.
    fn process_parent_process_id(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<ProcessId, VmiError>;

    /// Retrieves the architecture of a given process.
    fn process_architecture(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<OsArchitecture, VmiError>;

    /// Retrieves the translation root for a given process.
    ///
    /// The translation root is the root of the page table hierarchy (also
    /// known as the Directory Table Base (DTB) or Page Global Directory (PGD)).
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64**: The translation root corresponds with the CR3 register
    ///   and PML4 table.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `DirectoryTableBase` field from the
    ///   `KPROCESS` structure.
    /// - **Linux**: Retrieves the `mm->pgd` field from the `task_struct`.
    fn process_translation_root(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Pa, VmiError>;

    /// Retrieves the base address of the user translation root for a given
    /// process.
    ///
    /// If KPTI is disabled, this function will return the same value as
    /// [`VmiOs::process_translation_root`].
    fn process_user_translation_root(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Pa, VmiError>;

    /// Retrieves the filename of a given process.
    fn process_filename(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<String, VmiError>;

    /// Retrieves the base address of the process image.
    fn process_image_base(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Va, VmiError>;

    /// Retrieves a list of memory regions for a given process.
    fn process_regions(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
    ) -> Result<Vec<OsRegion>, VmiError>;

    /// Checks if a given virtual address is valid in a given process.
    fn process_address_is_valid(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError>;

    /// Finds a specific memory region in a process given an address.
    fn find_process_region(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<OsRegion>, VmiError>;

    /// Retrieves the architecture of an image at a given base address.
    fn image_architecture(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<OsArchitecture, VmiError>;

    /// Retrieves a list of exported symbols from an image at a given base
    /// address.
    fn image_exported_symbols(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        image_base: Va,
    ) -> Result<Vec<OsImageExportedSymbol>, VmiError>;

    /// Retrieves a specific syscall argument according to the system call ABI.
    ///
    /// This function assumes that it is called in the prologue of the system
    /// call handler, i.e., the instruction pointer is pointing to the first
    /// instruction of the function.
    fn syscall_argument(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    /// Retrieves a specific function argument according to the calling
    /// convention of the operating system.
    ///
    /// This function assumes that it is called in the function prologue,
    /// i.e., the instruction pointer is pointing to the first instruction of
    /// the function.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Assumes that the function is using the `stdcall`
    ///   calling convention.
    fn function_argument(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    /// Retrieves the return value of a function.
    ///
    /// This function assumes that it is called immediately after the function
    /// returns.
    fn function_return_value(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError>;

    /// Retrieves the last error value.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the value of the `NtCurrentTeb()->LastErrorValue`
    ///   field.
    ///   - See also: [`WindowsOs::last_status()`](../../../../vmi_os_windows/struct.WindowsOs.html#method.last_status)
    fn last_error(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<u32>, VmiError>;
}

/// Operating system extension trait.
pub trait OsExt<Driver>
where
    Driver: VmiDriver,
{
    /// Enumerates a linked list.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Enumerates a `LIST_ENTRY` structure.
    /// - **Linux**: Enumerates a `list_head` structure.
    fn enumerate_list(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        list_head: Va,
        callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError>;

    /// Enumerates a tree structure.
    ///
    /// # Platform-specific
    ///
    /// - **Windows 7**: Enumerates a `MMADDRESS_NODE` structure.
    /// - **Windows 10+**: Enumerates a `RTL_BALANCED_NODE` structure.
    fn enumerate_tree(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        root: Va,
        callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError>;
}
