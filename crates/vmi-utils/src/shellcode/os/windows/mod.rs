mod kernel_mode;
mod user_mode;

use vmi_arch_amd64::Amd64;
use vmi_core::driver::VmiMemory;
use vmi_os_windows::WindowsOs;

use super::{super::ShellcodeParameterSource, OsAdapter};
use crate::injector::Recipe;

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    type KernelRecipeData = kernel_mode::KernelShellcodeRecipeData;
    type UserRecipeData = user_mode::UserShellcodeRecipeData;

    fn kernel_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::kernel_shellcode_call_recipe(shellcode, parameter)
    }

    fn kernel_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::KernelRecipeData> {
        kernel_mode::kernel_shellcode_spawn_recipe(shellcode, parameter)
    }

    fn user_shellcode_call_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData> {
        user_mode::user_shellcode_call_recipe(shellcode, parameter)
    }

    fn user_shellcode_spawn_recipe(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ShellcodeParameterSource,
    ) -> Recipe<Self, Self::UserRecipeData> {
        user_mode::user_shellcode_spawn_recipe(shellcode, parameter)
    }
}
