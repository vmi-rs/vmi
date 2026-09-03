use vmi::{
    Registers as _, Va,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    trace::Hex,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

use super::{ShellcodeParameterSource, ShellcodePayload, ShellcodeRetryState};

/// Data retained while the kernel-mode shellcode recipe executes.
#[derive(Debug)]
pub struct KernelShellcodeRecipeData {
    payload: ShellcodePayload,
    retry: ShellcodeRetryState,
    kernel_image_base: Va,
    guest_address: u64,
}

impl KernelShellcodeRecipeData {
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        Self {
            payload: ShellcodePayload::new(shellcode, parameter),
            retry: ShellcodeRetryState::default(),
            kernel_image_base: Va(0),
            guest_address: 0,
        }
    }
}

/// Builds a synchronous kernel-mode shellcode recipe.
///
/// The SCFW kernel bootstrap receives the kernel image base in `argument1`. The
/// parameter source either appends an encoded block to the payload and passes
/// its guest address in `argument2`, or supplies the exact `argument2` value.
/// Once the shellcode call begins, the shellcode owns the allocation and must
/// release it with `ExFreePool` before returning.
///
/// Recoverable failures before the shellcode call restore the hijacked
/// registers and retry from the allocation step:
///
/// ```text
/// begin attempt
/// ├─ ExAllocatePool(page-aligned payload size)
/// ├─ retry if allocation failed
/// ├─ VMI write(shellcode + parameters)
/// ├─ on write failure: ExFreePool + retry
/// └─ shellcode(kernel image base, parameter)  # shellcode owns allocation
/// ```
#[tracing::instrument(name = "kernel_shellcode", skip_all)]
pub fn kernel_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = KernelShellcodeRecipeData::new(shellcode, parameter);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            #[expect(non_upper_case_globals)]
            const NonPagedPoolExecute: u64 = 0;

            let vmi = vmi!();

            let attempt = data![retry].begin_attempt(registers!());
            let allocation_size = data![payload].allocation_size;

            data![kernel_image_base] = vmi.os().kernel_image_base()?;

            tracing::debug!(
                attempt,
                size = allocation_size,
                "allocating kernel shellcode memory"
            );

            inject! {
                nt!ExAllocatePool(
                    NonPagedPoolExecute,            // PoolType
                    allocation_size                 // NumberOfBytes
                )
            }
        },
        {
            let vmi = vmi!();

            let guest_address = Va(vmi.registers().result());
            data![guest_address] = guest_address.0;

            let attempt = data![retry].attempt;
            let payload = &data![payload];

            if guest_address.is_null() {
                tracing::warn!(attempt, "kernel shellcode allocation failed, retrying");
                return Ok(RecipeControlFlow::Goto(0));
            }

            tracing::debug!(
                attempt,
                %guest_address,
                size = payload.bytes.len(),
                "writing kernel shellcode memory"
            );

            if let Err(err) = vmi.write(guest_address, &payload.bytes) {
                tracing::warn!(
                    %err,
                    attempt,
                    %guest_address,
                    "kernel shellcode write failed, freeing allocation and retrying"
                );

                inject! {
                    nt!ExFreePool(guest_address)    // P
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            let parameter = payload.parameter_value(guest_address.0);

            tracing::debug!(
                attempt,
                %guest_address,
                parameter = %Hex(parameter),
                "calling kernel shellcode"
            );

            inject! {
                guest_address(data![kernel_image_base], parameter)
            }
        },
    ]
}
