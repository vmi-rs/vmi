mod kernel_mode;
mod user_mode;

use vmi_core::driver::VmiMemory;
use vmi_os_windows::WindowsOs;

use super::{
    super::{ShellcodeParameterSource, arch::ArchAdapter},
    OsAdapter,
};
use crate::injector::{ArchAdapter as InjectorArchAdapter, OsAdapter as InjectorOsAdapter, Recipe};

impl<Driver> OsAdapter for WindowsOs<Driver>
where
    Driver: VmiMemory,
    Driver::Architecture: ArchAdapter + InjectorArchAdapter<Driver>,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    type KernelRecipeData = kernel_mode::KernelShellcodeRecipeData<Driver::Architecture>;
    type UserRecipeData = user_mode::UserShellcodeRecipeData<Driver::Architecture>;

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
