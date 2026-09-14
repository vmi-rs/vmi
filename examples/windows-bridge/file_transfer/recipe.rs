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
/// **Note:** We intentionally run the shellcode in a `call` mode (synchronously
/// on the current thread) rather than `spawn`ing a new thread. A spawned thread
/// would run in the `System` process, where the (process-local) file handle
/// is invalid.
pub fn file_transfer_recipe<Driver>(file_handle: u64) -> KernelShellcodeRecipe<WindowsOs<Driver>>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    kernel_shellcode_call_recipe(
        FILE_TRANSFER_SHELLCODE,
        ShellcodeParameterValue(file_handle),
    )
}
