use vmi::{
    Registers as _, Va, VmiError,
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
            #[expect(non_upper_case_globals)]
            const NonPagedPoolExecute: u64 = 0;

            inject! {
                nt!ExAllocatePool(
                    NonPagedPoolExecute,
                    FILE_TRANSFER_SHELLCODE.len()
                )
            }
        },
        {
            data![guest_address] = vmi!().registers().result();
            // REVIEW: retry
            if data![guest_address] == 0 {
                return Err(VmiError::Other("ExAllocatePool failed"));
            }

            // REVIEW: retry + ExFreePool
            vmi!().write(Va(data![guest_address]), FILE_TRANSFER_SHELLCODE)?;

            let kernel_image_base = vmi!().os().kernel_image_base()?;
            let shellcode = Va(data![guest_address]);

            inject! {
                shellcode(kernel_image_base, data![file_handle])
            }
        },
    ]
}
