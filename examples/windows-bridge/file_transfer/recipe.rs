use vmi::{
    Architecture as _, Registers as _, Va,
    arch::amd64::{Amd64, Registers},
    driver::VmiMemory,
    os::windows::WindowsOs,
    trace::Hex,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
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
    attempt: u64,
    original_registers: Option<Registers>,
}

impl FileTransferRecipeData {
    fn new(file_handle: u64) -> Self {
        Self {
            file_handle,
            guest_address: 0,
            attempt: 0,
            original_registers: None,
        }
    }

    fn begin_attempt(&mut self, registers: &mut Registers) -> u64 {
        match self.original_registers {
            Some(original_registers) => {
                tracing::debug!(
                    sp = %Va(original_registers.stack_pointer()),
                    "restoring registers for file-transfer retry"
                );
                *registers = original_registers;
            }
            None => {
                tracing::debug!(
                    sp = %Va(registers.stack_pointer()),
                    "saving registers for file transfer"
                );
                self.original_registers = Some(*registers);
            }
        }

        self.attempt += 1;
        self.attempt
    }
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
        Recipe::<WindowsOs<Driver>>::new(FileTransferRecipeData::new(file_handle)),
        {
            let attempt = data![begin_attempt(registers!())];
            let number_of_bytes = Amd64::va_align_up(Va(FILE_TRANSFER_SHELLCODE.len() as u64)).0;

            tracing::debug!(
                attempt,
                number_of_bytes,
                "allocating file-transfer shellcode"
            );

            #[expect(non_upper_case_globals)]
            const NonPagedPoolExecute: u64 = 0;

            inject! {
                nt!ExAllocatePool(
                    NonPagedPoolExecute,
                    number_of_bytes
                )
            }
        },
        {
            let vmi = vmi!();
            data![guest_address] = vmi.registers().result();

            let attempt = data![attempt];
            let guest_address = Va(data![guest_address]);

            if guest_address.is_null() {
                tracing::warn!(attempt, "shellcode allocation failed, retrying");
                return Ok(RecipeControlFlow::Goto(0));
            }

            tracing::debug!(
                attempt,
                %guest_address,
                file_handle = %Hex(data![file_handle]),
                "file-transfer shellcode allocation succeeded"
            );

            if let Err(err) = vmi.write(guest_address, FILE_TRANSFER_SHELLCODE) {
                tracing::warn!(
                    %err,
                    attempt,
                    %guest_address,
                    "shellcode write failed, freeing allocation and retrying"
                );

                inject! {
                    nt!ExFreePool(guest_address)
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            let kernel_image_base = vmi.os().kernel_image_base()?;

            inject! {
                guest_address(kernel_image_base, data![file_handle])
            }
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_attempt_captures_then_restores_registers() {
        let mut data = FileTransferRecipeData::new(0x1234);
        let original = Registers {
            rax: 1,
            rsp: 2,
            rip: 3,
            ..Registers::default()
        };
        let mut registers = original;

        assert_eq!(data.begin_attempt(&mut registers), 1);
        assert_eq!(data.original_registers, Some(original));

        registers.rax = 10;
        registers.rsp = 20;
        registers.rip = 30;

        assert_eq!(data.begin_attempt(&mut registers), 2);
        assert_eq!(registers, original);
    }
}
