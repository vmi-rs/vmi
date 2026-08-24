use vmi::{
    Va, VmiError,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    utils::injector::{Recipe, recipe},
};

/// File-transfer shellcode embedded from the selected SCFW build artifact.
const FILE_TRANSFER_SHELLCODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/scfw/build-x64/shellcodes/file-transfer/file-transfer.bin"
));

/// Executable nonpaged pool type used by the legacy allocation API.
const NON_PAGED_POOL_EXECUTE: u32 = 0;

/// Data retained while the kernel-mode shellcode recipe executes.
pub struct FileTransferRecipeData {
    file_handle: u64,
    guest_address: u64,
}

/// Builds the synchronous kernel-mode file-transfer recipe.
///
/// The shellcode receives the kernel image base in `argument1` for SCFW import
/// resolution and the process-local file handle in `argument2`.
pub fn file_transfer_recipe<Driver>(
    file_handle: u64,
) -> Recipe<WindowsOs<Driver>, FileTransferRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    recipe![
        Recipe::<WindowsOs<Driver>>::new(FileTransferRecipeData {
            file_handle,
            guest_address: 0,
        }),
        {
            inject! {
                nt!ExAllocatePool(
                    NON_PAGED_POOL_EXECUTE,
                    FILE_TRANSFER_SHELLCODE.len()
                )
            }
        },
        {
            data![guest_address] = vmi!().registers().rax;
            if data![guest_address] == 0 {
                return Err(VmiError::Other("ExAllocatePool failed"));
            }

            vmi!().write(Va(data![guest_address]), FILE_TRANSFER_SHELLCODE)?;

            let kernel_image_base = vmi!().os().kernel_image_base()?;
            let shellcode = Va(data![guest_address]);

            inject! {
                shellcode(kernel_image_base, data![file_handle])
            }
        },
    ]
}
