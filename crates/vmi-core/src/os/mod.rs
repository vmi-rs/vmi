#![doc = include_str!("../../docs/os.md")]

mod dummy;
mod image;
mod mapped;
mod module;
mod process;
mod region;
mod struct_reader;
mod thread;

use vmi_macros::derive_os_wrapper;

pub use self::{
    dummy::NoOS,
    image::{VmiOsImageArchitecture, VmiOsImageSymbol, VmiOsImage},
    mapped::VmiOsMapped,
    module::VmiOsModule,
    process::{ProcessId, ProcessObject, VmiOsProcess},
    region::{VmiOsRegion, VmiOsRegionKind},
    struct_reader::StructReader,
    thread::{ThreadId, ThreadObject, VmiOsThread},
};
use crate::{Va, VmiDriver, VmiError, VmiOsState, VmiState};

/// Operating system trait.
#[expect(clippy::needless_lifetimes)]
#[derive_os_wrapper(VmiOsState)]
pub trait VmiOs<Driver>: Sized
where
    Driver: VmiDriver,
{
    /// The process type.
    type Process<'a>: VmiOsProcess<'a, Driver> + 'a
    where
        Self: 'a;

    /// The thread type.
    type Thread<'a>: VmiOsThread<'a, Driver> + 'a
    where
        Self: 'a;

    /// The image type.
    type Image<'a>: VmiOsImage<'a, Driver> + 'a
    where
        Self: 'a;

    /// The kernel module type.
    type Module<'a>: VmiOsModule<'a, Driver> + 'a
    where
        Self: 'a;

    /// The memory region type.
    type Region<'a>: VmiOsRegion<'a, Driver> + 'a
    where
        Self: 'a;

    /// The memory mapped region type.
    type Mapped<'a>: VmiOsMapped<'a, Driver> + 'a
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
    fn kernel_image_base(vmi: VmiState<Driver, Self>) -> Result<Va, VmiError>;

    /// Retrieves an implementation-specific string containing kernel
    /// information.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `NtBuildLab` string from the kernel image.
    /// - **Linux**: Retrieves the `linux_banner` string from the kernel image.
    fn kernel_information_string(vmi: VmiState<Driver, Self>) -> Result<String, VmiError>;

    /// Checks if Kernel Page Table Isolation (KPTI) is enabled.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `KiKvaShadow` global variable, if it exists.
    fn kpti_enabled(vmi: VmiState<Driver, Self>) -> Result<bool, VmiError>;

    /// Returns an iterator over the loaded kernel modules.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves information from the `PsLoadedModuleList`.
    /// - **Linux**: Retrieves information from the `modules` list.
    fn modules<'a>(
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Module<'a>, VmiError>> + 'a, VmiError>;

    /// Returns an iterator over the processes.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves information from the `PsActiveProcessHead` list.
    /// - **Linux**: Retrieves information from the `tasks` list.
    fn processes<'a>(
        vmi: VmiState<'a, Driver, Self>,
    ) -> Result<impl Iterator<Item = Result<Self::Process<'a>, VmiError>> + 'a, VmiError>;

    /// Returns the process corresponding to the given process object.
    fn process<'a>(
        vmi: VmiState<'a, Driver, Self>,
        process: ProcessObject,
    ) -> Result<Self::Process<'a>, VmiError>;

    /// Returns the currently executing process.
    fn current_process<'a>(vmi: VmiState<'a, Driver, Self>) -> Result<Self::Process<'a>, VmiError>;

    /// Returns the system process object.
    ///
    /// The system process is the first process created by the kernel.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the `PsInitialSystemProcess` global variable.
    /// - **Linux**: Retrieves the `init_task` global variable.
    fn system_process<'a>(vmi: VmiState<'a, Driver, Self>) -> Result<Self::Process<'a>, VmiError>;

    /// Returns the thread corresponding to the given thread object.
    fn thread<'a>(
        vmi: VmiState<'a, Driver, Self>,
        thread: ThreadObject,
    ) -> Result<Self::Thread<'a>, VmiError>;

    /// Returns the currently executing thread.
    fn current_thread<'a>(vmi: VmiState<'a, Driver, Self>) -> Result<Self::Thread<'a>, VmiError>;

    /// Returns the image corresponding to the given base address.
    fn image<'a>(
        vmi: VmiState<'a, Driver, Self>,
        image_base: Va,
    ) -> Result<Self::Image<'a>, VmiError>;

    /// Returns the kernel module corresponding to the given base address.
    fn module<'a>(
        vmi: VmiState<'a, Driver, Self>,
        module: Va,
    ) -> Result<Self::Module<'a>, VmiError>;

    /// Returns the memory region corresponding to the given address.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: The region is represented by the `_MMVAD` structure.
    /// - **Linux**: The region is represented by the `vm_area_struct` structure.
    fn region<'a>(
        vmi: VmiState<'a, Driver, Self>,
        region: Va,
    ) -> Result<Self::Region<'a>, VmiError>;

    /// Retrieves a specific syscall argument according to the system call ABI.
    ///
    /// This function assumes that it is called in the prologue of the system
    /// call handler, i.e., the instruction pointer is pointing to the first
    /// instruction of the function.
    fn syscall_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError>;

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
    fn function_argument(vmi: VmiState<Driver, Self>, index: u64) -> Result<u64, VmiError>;

    /// Retrieves the return value of a function.
    ///
    /// This function assumes that it is called immediately after the function
    /// returns.
    fn function_return_value(vmi: VmiState<Driver, Self>) -> Result<u64, VmiError>;

    /// Retrieves the last error value.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: Retrieves the value of the `NtCurrentTeb()->LastErrorValue`
    ///   field.
    ///   - See also: [`WindowsOs::last_status()`](../../../../vmi_os_windows/struct.WindowsOs.html#method.last_status)
    fn last_error(vmi: VmiState<Driver, Self>) -> Result<Option<u32>, VmiError>;
}
