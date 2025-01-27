#![doc = include_str!("../../docs/os.md")]

mod common;
mod image;
mod module;
mod process;
mod region;
mod struct_reader;
mod thread;

use vmi_macros::derive_os_wrapper;

pub use self::{
    common::{
        OsArchitecture, OsImageExportedSymbol, OsMapped, OsModule, OsProcess, OsRegion,
        OsRegionKind, ProcessId, ProcessObject, ThreadId, ThreadObject,
    },
    image::VmiOsImage,
    module::VmiOsModule,
    process::VmiOsProcess,
    region::VmiOsRegion,
    struct_reader::StructReader,
    thread::VmiOsThread,
};
use crate::{Va, VmiDriver, VmiError, VmiOsState, VmiState};

/// Operating system trait.
#[derive_os_wrapper(VmiOsState)]
pub trait VmiOs<Driver>: Sized
where
    Driver: VmiDriver,
{
    /// The process object type.
    type Process<'a>: VmiOsProcess<'a, Driver> + 'a
    where
        Self: 'a;

    /// The thread object type.
    type Thread<'a>: VmiOsThread<'a, Driver> + 'a
    where
        Self: 'a;

    /// The image object type.
    type Image<'a>: VmiOsImage<'a, Driver> + 'a
    where
        Self: 'a;

    /// The module object type.
    type Module<'a>: VmiOsModule<'a, Driver> + 'a
    where
        Self: 'a;

    /// The region object type.
    type Region<'a>: VmiOsRegion<'a, Driver> + 'a
    where
        Self: 'a;

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
    fn kernel_image_base(&self, vmi: VmiState<Driver, Self>) -> Result<Va, VmiError>;

    /// Retrieves an implementation-specific string containing kernel
    /// information.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `NtBuildLab` string from the kernel image.
    /// - **Linux**: Retrieves the `linux_banner` string from the kernel image.
    fn kernel_information_string(&self, vmi: VmiState<Driver, Self>) -> Result<String, VmiError>;

    /// Checks if Kernel Page Table Isolation (KPTI) is enabled.
    fn kpti_enabled(&self, vmi: VmiState<Driver, Self>) -> Result<bool, VmiError>;

    /// Returns an iterator over the loaded kernel modules.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves information from the `PsLoadedModuleList`.
    /// - **Linux**: Retrieves information from the `modules` list.
    fn __modules<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + 'a, VmiError>;

    /// XXX
    fn __processes<'a>(
        &'a self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + 'a, VmiError>;

    /// XXX
    fn __process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'a>, VmiError>;

    /// XXX
    fn __current_process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Process<'a>, VmiError>;

    /// Returns the system process object.
    ///
    /// The system process is the first process created by the kernel.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `PsInitialSystemProcess` global variable.
    /// - **Linux**: Retrieves the `init_task` global variable.
    fn __system_process<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Process<'a>, VmiError>;

    /// XXX
    fn __thread<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        thread: ThreadObject,
    ) -> Result<Self::Thread<'a>, VmiError>;

    /// XXX
    fn __current_thread<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<Self::Thread<'a>, VmiError>;

    /// XXX
    fn __image<'a>(
        &self,
        vmi: VmiState<'a, Driver, Self>,
        image_base: Va,
    ) -> Result<Self::Image<'a>, VmiError>;

    /// Retrieves a specific syscall argument according to the system call ABI.
    ///
    /// This function assumes that it is called in the prologue of the system
    /// call handler, i.e., the instruction pointer is pointing to the first
    /// instruction of the function.
    fn syscall_argument(&self, vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError>;

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
    fn function_argument(&self, vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError>;

    /// Retrieves the return value of a function.
    ///
    /// This function assumes that it is called immediately after the function
    /// returns.
    fn function_return_value(&self, vmi: VmiState<Driver, Self>) -> Result<u64, VmiError>;

    /// Retrieves the last error value.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the value of the `NtCurrentTeb()->LastErrorValue`
    ///   field.
    ///   - See also: [`WindowsOs::last_status()`](../../../../vmi_os_windows/struct.WindowsOs.html#method.last_status)
    fn last_error(&self, vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError>;
}

/// Operating system extension trait.
pub trait OsExt<Driver>: VmiOs<Driver>
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
        vmi: VmiState<Driver, Self>,
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
        vmi: VmiState<Driver, Self>,
        root: Va,
        callback: impl FnMut(Va) -> bool,
    ) -> Result<(), VmiError>;
}
