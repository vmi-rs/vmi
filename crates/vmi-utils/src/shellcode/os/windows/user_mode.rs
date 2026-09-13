use vmi_arch_amd64::Amd64;
use vmi_core::{Registers as _, Va, driver::VmiMemory, trace::Hex};
use vmi_os_windows::WindowsOs;

use super::super::super::{
    ShellcodeParameterSource, payload::ShellcodePayload, recipe::ShellcodeRetryState,
};
use crate::injector::{Recipe, RecipeControlFlow, recipe};

/// Data retained while the user-mode shellcode recipe executes.
#[derive(Debug)]
pub struct UserShellcodeRecipeData {
    payload: ShellcodePayload,
    retry: ShellcodeRetryState<Amd64>,
    guest_address: Va,
    thread_handle: u64,
}

impl UserShellcodeRecipeData {
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        Self {
            payload: ShellcodePayload::new(shellcode, parameter),
            retry: ShellcodeRetryState::default(),
            guest_address: Va::null(),
            thread_handle: 0,
        }
    }
}

fn prepare_user_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, UserShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = UserShellcodeRecipeData::new(shellcode, parameter);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        //
        // Step 1:
        // - Restore the original registers when retrying.
        // - Allocate executable memory for the payload.
        //
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            let attempt = data![retry].begin_attempt(registers!());
            let payload_size = data![payload].bytes.len();

            tracing::debug!(attempt, size = payload_size, "allocating shellcode memory");

            inject! {
                kernel32!VirtualAlloc(
                    0,                              // lpAddress
                    payload_size,                   // dwSize
                    MEM_COMMIT | MEM_RESERVE,       // flAllocationType
                    PAGE_EXECUTE_READWRITE          // flProtect
                )
            }
        },
        //
        // Step 2:
        // - Verify the allocation.
        //   - If the allocation fails, retry.
        // - Materialize its demand-zero pages from guest context.
        //
        {
            let vmi = vmi!();

            let guest_address = Va(vmi.registers().result());
            data![guest_address] = guest_address;

            let attempt = data![retry].attempt;
            let payload_size = data![payload].bytes.len();

            if guest_address.is_null() {
                tracing::warn!(attempt, "shellcode allocation failed, retrying");
                return Ok(RecipeControlFlow::Goto(0));
            }

            tracing::debug!(
                attempt,
                %guest_address,
                size = payload_size,
                "materializing memory"
            );

            inject! {
                kernel32!RtlFillMemory(
                    guest_address,                  // Destination
                    payload_size,                   // Length
                    0                               // Fill
                )
            }
        },
        //
        // Step 3:
        // - Write the payload into the memory.
        //   - If the write fails, free the allocation and retry.
        //
        {
            const MEM_RELEASE: u64 = 0x8000;

            let vmi = vmi!();

            let guest_address = data![guest_address];
            let attempt = data![retry].attempt;
            let payload = &data![payload];

            tracing::debug!(
                attempt,
                %guest_address,
                size = payload.bytes.len(),
                "writing shellcode"
            );

            if let Err(err) = vmi.write(guest_address, &payload.bytes) {
                tracing::warn!(
                    %err,
                    attempt,
                    %guest_address,
                    "shellcode write failed, retrying"
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

            Ok(RecipeControlFlow::Continue)
        },
    ]
}

/// Builds a user-mode shellcode recipe that calls the payload on the hijacked thread.
///
/// Once the shellcode call begins, the shellcode owns the allocation and must
/// release it with `VirtualFree` before returning.
///
/// Recoverable failures before the shellcode call restore the hijacked
/// registers and retry from the allocation step.
///
/// # Equivalent C pseudo-code
///
/// `VmiWrite` represents the host-side write into guest memory.
///
/// ```c
/// for (;;) {
///     PVOID Shellcode = VirtualAlloc(NULL,
///                                    PayloadSize,
///                                    MEM_COMMIT | MEM_RESERVE,
///                                    PAGE_EXECUTE_READWRITE);
///
///     if (!Shellcode) {
///         continue;
///     }
///
///     RtlFillMemory(Shellcode, PayloadSize, 0);
///
///     if (!VmiWrite(Shellcode, PayloadBytes, PayloadSize)) {
///         VirtualFree(Shellcode, 0, MEM_RELEASE);
///         continue;
///     }
///
///     ((void (*)(PVOID, PVOID))Shellcode)(Parameter, NULL);
///     break;
/// }
/// ```
#[tracing::instrument(name = "user_shellcode_call", skip_all)]
pub fn user_shellcode_call_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, UserShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    recipe![
        prepare_user_shellcode_recipe::<Driver>(shellcode, parameter),
        //
        // Step 4:
        // - Resolve the parameter and call the shellcode.
        //
        {
            let guest_address = data![guest_address];
            let attempt = data![retry].attempt;
            let parameter = data![payload].parameter_value(guest_address);

            tracing::debug!(
                attempt,
                %guest_address,
                parameter = %Hex(parameter),
                "invoking shellcode"
            );

            inject! {
                guest_address(
                    parameter,                     // argument1
                    0                              // argument2
                )
            }
        },
    ]
}

/// Builds a user-mode shellcode recipe that spawns a new payload thread.
///
/// Once `CreateThread` succeeds, the shellcode owns the allocation and must
/// release it with `VirtualFree` before completing.
///
/// Recoverable failures before thread creation restore the hijacked registers
/// and retry from the allocation step.
///
/// # Equivalent C pseudo-code
///
/// `VmiWrite` represents the host-side write into guest memory.
///
/// ```c
/// for (;;) {
///     PVOID Shellcode = VirtualAlloc(NULL,
///                                    PayloadSize,
///                                    MEM_COMMIT | MEM_RESERVE,
///                                    PAGE_EXECUTE_READWRITE);
///
///     if (!Shellcode) {
///         continue;
///     }
///
///     RtlFillMemory(Shellcode, PayloadSize, 0);
///
///     if (!VmiWrite(Shellcode, PayloadBytes, PayloadSize)) {
///         VirtualFree(Shellcode, 0, MEM_RELEASE);
///         continue;
///     }
///
///     HANDLE hThread = CreateThread(NULL,
///                                   0,
///                                   Shellcode,
///                                   Parameter,
///                                   0,
///                                   NULL);
///
///     if (!hThread) {
///         VirtualFree(Shellcode, 0, MEM_RELEASE);
///         continue;
///     }
///
///     CloseHandle(hThread);
///     break;
/// }
/// ```
#[tracing::instrument(name = "user_shellcode_spawn", skip_all)]
pub fn user_shellcode_spawn_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, UserShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    recipe![
        prepare_user_shellcode_recipe::<Driver>(shellcode, parameter),
        //
        // Step 4:
        // - Resolve the parameter and create the shellcode thread.
        //
        {
            let guest_address = data![guest_address];
            let attempt = data![retry].attempt;
            let parameter = data![payload].parameter_value(guest_address);

            tracing::debug!(
                attempt,
                start_address = %guest_address,
                parameter = %Hex(parameter),
                "launching shellcode thread"
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
        //
        // Step 5:
        // - Verify thread creation.
        //   - If creation fails, free the allocation and retry.
        // - Close the thread handle.
        //
        {
            const MEM_RELEASE: u64 = 0x8000;

            let vmi = vmi!();

            let thread_handle = vmi.registers().result();
            data![thread_handle] = thread_handle;

            let attempt = data![retry].attempt;

            if thread_handle == 0 {
                let guest_address = data![guest_address];

                tracing::warn!(
                    attempt,
                    %guest_address,
                    "shellcode thread creation failed, retrying"
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
                "closing shellcode thread handle"
            );

            inject! {
                kernel32!CloseHandle(thread_handle) // hObject
            }
        },
    ]
}
