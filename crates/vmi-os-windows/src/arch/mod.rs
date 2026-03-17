#[cfg(feature = "arch-amd64")]
mod amd64;

#[cfg(feature = "arch-aarch64")]
mod aarch64;

use vmi_core::{Architecture, Pa, Va, VmiCore, VmiError, VmiState, driver::VmiRead, os::VmiOsImageArchitecture};

#[cfg(feature = "arch-amd64")]
pub use self::amd64::{WindowsExceptionVector, WindowsInterrupt, WindowsPageTableEntry};

use crate::{WindowsKernelInformation, WindowsOs};

/// Architecture-specific Windows functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiRead<Architecture = Self>,
{
    fn syscall_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    fn function_argument(vmi: VmiState<WindowsOs<Driver>>, index: u64) -> Result<u64, VmiError>;

    fn function_return_value(vmi: VmiState<WindowsOs<Driver>>) -> Result<u64, VmiError>;

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    fn kernel_image_base(vmi: VmiState<WindowsOs<Driver>>) -> Result<Va, VmiError>;

    fn is_page_present_or_transition(
        vmi: VmiState<WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError>;

    fn current_kpcr(vmi: VmiState<WindowsOs<Driver>>) -> Va;

    /// Convert a raw register value (e.g., DirectoryTableBase) to a physical address
    /// suitable as a translation root.
    fn translation_root_from_raw(value: u64) -> Pa;

    /// Return the native image architecture for this architecture.
    /// This is used to determine the architecture of non-WoW64 processes.
    fn native_image_architecture() -> VmiOsImageArchitecture;
}
