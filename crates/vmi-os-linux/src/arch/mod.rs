mod amd64;

use vmi_core::{Architecture, Va, VmiCore, VmiDriver, VmiError};

use crate::LinuxOs;

pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_argument(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_return_value(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError>;

    fn find_banner(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<String>, VmiError>;

    fn kernel_image_base(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Va, VmiError>;

    fn kaslr_offset(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<u64, VmiError>;

    fn per_cpu(
        os: &LinuxOs<Driver>,
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Va;
}
