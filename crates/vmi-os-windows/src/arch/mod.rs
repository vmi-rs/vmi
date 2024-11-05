mod amd64;

use vmi_core::{os::ProcessObject, Architecture, Va, VmiCore, VmiDriver, VmiError};

use crate::{WindowsKernelInformation, WindowsOs};

/// Architecture-specific Windows functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_argument(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_return_value(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError>;

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    fn kernel_image_base(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError>;

    fn process_address_is_valid(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError>;

    fn current_kpcr(
        os: &WindowsOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Va;
}
