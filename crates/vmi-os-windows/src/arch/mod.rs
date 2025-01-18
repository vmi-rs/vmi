mod amd64;

use vmi_core::{os::ProcessObject, Architecture, Va, VmiCore, VmiDriver, VmiError, VmiWithRegisters};

use crate::{WindowsKernelInformation, WindowsOs};

/// Architecture-specific Windows functionality.
pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        vmi: &impl VmiWithRegisters<Driver>,
        os: &WindowsOs<Driver>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_argument(
        vmi: &impl VmiWithRegisters<Driver>,
        os: &WindowsOs<Driver>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_return_value(
        vmi: &impl VmiWithRegisters<Driver>,
        os: &WindowsOs<Driver>,
    ) -> Result<u64, VmiError>;

    fn find_kernel(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<WindowsKernelInformation>, VmiError>;

    fn kernel_image_base(
        vmi: &impl VmiWithRegisters<Driver>,
        os: &WindowsOs<Driver>,
    ) -> Result<Va, VmiError>;

    fn process_address_is_valid(
        vmi: &impl VmiWithRegisters<Driver>,
        os: &WindowsOs<Driver>,
        process: ProcessObject,
        address: Va,
    ) -> Result<Option<bool>, VmiError>;

    fn current_kpcr(vmi: &impl VmiWithRegisters<Driver>, os: &WindowsOs<Driver>) -> Va;
}
