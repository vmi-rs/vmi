use vmi::{
    Registers as _, Va,
    arch::amd64::Amd64,
    driver::VmiMemory,
    os::windows::WindowsOs,
    trace::Hex,
    utils::injector::{Recipe, RecipeControlFlow, recipe},
};

use super::{ShellcodeParameterSource, ShellcodePayload, ShellcodeRetryState};

/// Data retained while the user-mode shellcode recipe executes.
#[derive(Debug)]
pub struct UserShellcodeRecipeData {
    payload: ShellcodePayload,
    retry: ShellcodeRetryState,
    guest_address: u64,
    thread_handle: u64,
}

impl UserShellcodeRecipeData {
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        Self {
            payload: ShellcodePayload::new(shellcode, parameter),
            retry: ShellcodeRetryState::default(),
            guest_address: 0,
            thread_handle: 0,
        }
    }
}

/// Builds an asynchronous user-mode shellcode recipe.
///
/// The parameter source either appends an encoded block to the payload and
/// passes its guest address through `CreateThread::lpParameter`, or supplies the
/// exact `lpParameter` value. Once `CreateThread` succeeds, the shellcode owns
/// the allocation and must release it with `VirtualFree` before completing.
///
/// Recoverable failures before thread creation restore the hijacked registers
/// and retry from the allocation step:
///
/// ```text
/// begin attempt
/// ├─ VirtualAlloc(page-aligned payload size)
/// ├─ retry if allocation failed
/// ├─ RtlFillMemory(payload bytes)          # materialize demand-zero pages
/// ├─ VMI write(shellcode + parameters)
/// ├─ on write failure: VirtualFree + retry
/// ├─ CreateThread(shellcode, parameter)
/// ├─ on creation failure: VirtualFree + retry
/// └─ CloseHandle(created thread handle)    # shellcode owns allocation
/// ```
#[tracing::instrument(name = "user_shellcode", skip_all)]
pub fn user_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, UserShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = UserShellcodeRecipeData::new(shellcode, parameter);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            let attempt = data![retry].begin_attempt(registers!());
            let allocation_size = data![payload].allocation_size;

            tracing::debug!(
                attempt,
                size = allocation_size,
                "allocating user shellcode memory"
            );

            inject! {
                kernel32!VirtualAlloc(
                    0,                              // lpAddress
                    allocation_size,                // dwSize
                    MEM_COMMIT | MEM_RESERVE,       // flAllocationType
                    PAGE_EXECUTE_READWRITE          // flProtect
                )
            }
        },
        {
            let vmi = vmi!();

            let guest_address = Va(vmi.registers().result());
            data![guest_address] = guest_address.0;

            let attempt = data![retry].attempt;
            let payload_size = data![payload].bytes.len();

            if guest_address.is_null() {
                tracing::warn!(attempt, "user shellcode allocation failed, retrying");
                return Ok(RecipeControlFlow::Goto(0));
            }

            tracing::debug!(
                attempt,
                %guest_address,
                size = payload_size,
                "materializing user shellcode memory"
            );

            inject! {
                kernel32!RtlFillMemory(
                    guest_address,                  // Destination
                    payload_size,                   // Length
                    0                               // Fill
                )
            }
        },
        {
            const MEM_RELEASE: u64 = 0x8000;

            let vmi = vmi!();

            let guest_address = Va(data![guest_address]);
            let attempt = data![retry].attempt;
            let payload = &data![payload];

            if let Err(err) = vmi.write(guest_address, &payload.bytes) {
                tracing::warn!(
                    %err,
                    attempt,
                    %guest_address,
                    "user shellcode write failed, freeing allocation and retrying"
                );

                inject! {
                    kernel32!VirtualFree(
                        guest_address,              // lpAddress
                        0,                          // dwSize
                        MEM_RELEASE                 // dwFreeType
                    )
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            let parameter = payload.parameter_value(guest_address.0);

            tracing::debug!(
                attempt,
                start_address = %guest_address,
                parameter = %Hex(parameter),
                "launching user shellcode thread"
            );

            inject! {
                kernel32!CreateThread(
                    0,                              // lpThreadAttributes
                    0,                              // dwStackSize
                    guest_address,                  // lpStartAddress
                    parameter,                      // lpParameter
                    0,                              // dwCreationFlags
                    0                               // lpThreadId
                )
            }
        },
        {
            const MEM_RELEASE: u64 = 0x8000;

            let vmi = vmi!();

            let thread_handle = vmi.registers().result();
            data![thread_handle] = thread_handle;

            let attempt = data![retry].attempt;

            if thread_handle == 0 {
                let guest_address = Va(data![guest_address]);

                tracing::warn!(
                    attempt,
                    %guest_address,
                    "user shellcode thread creation failed, freeing allocation and retrying"
                );

                inject! {
                    kernel32!VirtualFree(
                        guest_address,              // lpAddress
                        0,                          // dwSize
                        MEM_RELEASE                 // dwFreeType
                    )
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            tracing::debug!(
                thread_handle = %Hex(thread_handle),
                "closing user shellcode thread handle"
            );

            inject! {
                kernel32!CloseHandle(thread_handle) // hObject
            }
        },
    ]
}
