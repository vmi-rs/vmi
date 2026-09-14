use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{
        KernelShellcodeRecipe, kernel_shellcode_call_recipe, kernel_shellcode_spawn_recipe,
    },
};

use super::parameters::KernelFileParameters;

/// Kernel-file shellcode embedded from the selected `scfw` build artifact.
const KERNEL_FILE_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/kernel-file.bin"
));

/// Builds the kernel-file recipe that calls the payload on the hijacked thread.
///
/// The recipe completes only after the payload has created the file and
/// returned, so the hijacked thread performs the file I/O itself.
#[tracing::instrument(name = "kernel_file_call", skip_all)]
pub fn kernel_file_call_recipe<Driver>(
    parameters: &KernelFileParameters,
) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_call_recipe(KERNEL_FILE_SHELLCODE, parameters)
}

/// Builds the kernel-file recipe that spawns a system thread for the payload.
///
/// The recipe completes once the thread has been created; the file I/O then
/// runs in the System process, and the terminal bridge status arrives after
/// the injector has already torn its monitoring down.
#[tracing::instrument(name = "kernel_file_spawn", skip_all)]
pub fn kernel_file_spawn_recipe<Driver>(
    parameters: &KernelFileParameters,
) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_spawn_recipe(KERNEL_FILE_SHELLCODE, parameters)
}
