mod kernel_mode;
mod user_mode;

use vmi_core::{driver::VmiMemory, os::ProcessId};
use vmi_os_windows::WindowsOs;

use super::{
    super::{ParameterSource, RetryPolicy, arch::ArchAdapter},
    OsAdapter,
};
use crate::injector::{ArchAdapter as InjectorArchAdapter, OsAdapter as InjectorOsAdapter, Recipe};

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiMemory,
    Driver::Architecture:
        ArchAdapter + InjectorArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    type KernelRecipeData = kernel_mode::KernelRecipeData<Driver::Architecture>;
    type UserRecipeData = user_mode::UserRecipeData<Driver::Architecture>;

    fn kernel_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::kernel_shellcode_call_recipe(shellcode, parameter, retry)
    }

    fn kernel_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::kernel_shellcode_spawn_recipe(shellcode, parameter, retry)
    }

    fn user_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::UserRecipeData> {
        user_mode::user_shellcode_call_recipe(shellcode, parameter, retry)
    }

    fn user_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Recipe<Self, Self::UserRecipeData> {
        user_mode::user_shellcode_spawn_recipe(shellcode, parameter, retry)
    }

    fn user_shellcode_spawn_from_kernel_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
        pid: ProcessId,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::user_shellcode_spawn_from_kernel_recipe(shellcode, parameter, retry, pid)
    }
}
