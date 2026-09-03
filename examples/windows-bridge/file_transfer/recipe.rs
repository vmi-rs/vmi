use vmi::{arch::amd64::Amd64, driver::VmiMemory, os::windows::WindowsOs, utils::injector::Recipe};

use crate::bridge::{KernelShellcodeRecipeData, ShellcodeParameterValue, kernel_shellcode_recipe};

/// File-transfer shellcode embedded from the selected SCFW build artifact.
const FILE_TRANSFER_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/scfw/build-x64/shellcodes/file-transfer/file-transfer.bin"
));

/// Builds the kernel-mode file-transfer recipe for a process-local handle.
///
/// The generic kernel recipe supplies the kernel image base to the SCFW
/// bootstrap and passes `file_handle` through its second argument unchanged.
pub fn file_transfer_recipe<Driver>(
    file_handle: u64,
) -> Recipe<WindowsOs<Driver>, KernelShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_recipe(
        FILE_TRANSFER_SHELLCODE,
        ShellcodeParameterValue(file_handle),
    )
}
