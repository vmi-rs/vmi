mod amd64;

use vmi_core::{Architecture, Va, VmiCore, VmiError, VmiState, driver::VmiRead};

pub use self::amd64::{WindowsExceptionVector, WindowsInterrupt, WindowsPageTableEntry};
use crate::{WindowsKernelInformation, WindowsOs};

/// Architecture-specific Windows functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiRead<Architecture = Self>,
{
    fn syscall_argument(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_argument(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_return_value(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Result<u64, VmiError>;

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    fn kernel_image_base(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Result<Va, VmiError>;

    fn is_page_present_or_transition(
        vmi: VmiState<Driver, WindowsOs<Driver>>,
        address: Va,
    ) -> Result<bool, VmiError>;

    fn current_kpcr(vmi: VmiState<Driver, WindowsOs<Driver>>) -> Va;
}
