use vmi::{
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::shellcode::{
        KernelShellcodeRecipe, ShellcodeParameterValue, kernel_shellcode_call_recipe,
    },
};

/// Compiled `file-transfer` shellcode.
const FILE_TRANSFER_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/shellcodes/bin/x64/file-transfer.bin"
));

/// Builds a recipe that runs the `file-transfer` shellcode on the thread
/// executing `NtClose`.
///
/// The call recipe passes the kernel image base as the first and the
/// `file_handle` as the second argument.
///
/// **Note:** The transfer runs on the same thread that called `NtClose`.
/// It reads the file before Windows closes the handle.
///
/// This keeps the transfer in the process where the handle refers to
/// the file we want to read. The recipe for starting a new kernel thread
/// (`spawn`) would run the transfer in the `System` process instead, where
/// the same handle might refer to a different file or no file at all.
pub fn file_transfer_recipe<Driver>(file_handle: u64) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_call_recipe(
        FILE_TRANSFER_SHELLCODE,
        ShellcodeParameterValue(file_handle),
    )
}
