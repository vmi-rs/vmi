mod amd64;

use vmi_core::{Architecture, Va, VmiCore, VmiDriver, VmiError, VmiState};

use crate::LinuxOs;

pub trait ArchAdapter<Driver>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
{
    fn syscall_argument(
        vmi: &VmiState<Driver, LinuxOs<Driver>>,
        os: &LinuxOs<Driver>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_argument(
        vmi: &VmiState<Driver, LinuxOs<Driver>>,
        os: &LinuxOs<Driver>,
        index: u64,
    ) -> Result<u64, VmiError>;

    fn function_return_value(
        vmi: &VmiState<Driver, LinuxOs<Driver>>,
        os: &LinuxOs<Driver>,
    ) -> Result<u64, VmiError>;

    fn find_banner(
        vmi: &VmiCore<Driver>,
        registers: &<Driver::Architecture as Architecture>::Registers,
    ) -> Result<Option<String>, VmiError>;

    fn kernel_image_base(
        vmi: &VmiState<Driver, LinuxOs<Driver>>,
        os: &LinuxOs<Driver>,
    ) -> Result<Va, VmiError>;

    fn kaslr_offset(
        vmi: &VmiState<Driver, LinuxOs<Driver>>,
        os: &LinuxOs<Driver>,
    ) -> Result<u64, VmiError>;

    fn per_cpu(vmi: &VmiState<Driver, LinuxOs<Driver>>, os: &LinuxOs<Driver>) -> Va;
}
