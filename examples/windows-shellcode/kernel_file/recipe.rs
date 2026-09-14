use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{
        KernelShellcodeRecipe, kernel_shellcode_call_recipe, kernel_shellcode_spawn_recipe,
    },
};

use super::parameters::KernelFileParameters;

/// Compiled `kernel-file` shellcode.
const KERNEL_FILE_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/kernel-file.bin"
));

/// Builds a recipe that runs the `kernel-file` shellcode on the hijacked thread.
///
/// The recipe completes after the shellcode returns.
#[tracing::instrument(name = "kernel_file_call", skip_all)]
pub fn kernel_file_call_recipe<Driver>(
    parameters: &KernelFileParameters,
) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_call_recipe(KERNEL_FILE_SHELLCODE, parameters)
}

/// Builds a recipe that runs the `kernel-file` shellcode on a system thread.
///
/// The recipe completes once the system thread has been created.
/// The injector remains active until the shellcode reports its final status.
#[tracing::instrument(name = "kernel_file_spawn", skip_all)]
pub fn kernel_file_spawn_recipe<Driver>(
    parameters: &KernelFileParameters,
) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_spawn_recipe(KERNEL_FILE_SHELLCODE, parameters)
}
