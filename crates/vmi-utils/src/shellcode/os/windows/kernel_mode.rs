use vmi_arch_amd64::Amd64;
use vmi_core::{Registers as _, Va, driver::VmiMemory, trace::Hex};
use vmi_os_windows::WindowsOs;

use super::super::super::{
    ShellcodeParameterSource, payload::ShellcodePayload, recipe::ShellcodeRetryState,
};
use crate::injector::{Recipe, RecipeControlFlow, recipe};

/// Data retained while the kernel-mode shellcode recipe executes.
#[derive(Debug)]
pub struct KernelShellcodeRecipeData {
    payload: ShellcodePayload,
    retry: ShellcodeRetryState<Amd64>,
    kernel_image_base: Va,
    guest_address: Va,
    thread_handle_ptr: Va,
}

impl KernelShellcodeRecipeData {
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        Self {
            payload: ShellcodePayload::new(shellcode, parameter),
            retry: ShellcodeRetryState::default(),
            kernel_image_base: Va::null(),
            guest_address: Va::null(),
            thread_handle_ptr: Va::null(),
        }
    }
}

/// Builds the steps shared by every kernel-mode shellcode recipe.
///
/// The allocation covers the whole payload, so a caller that needs trailing
/// guest memory reserves it inside `shellcode`. The payload owns the
/// allocation and releases it with `ExFreePool`, so anything reserved that
/// way must not outlive the payload.
fn prepare_kernel_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    let data = KernelShellcodeRecipeData::new(shellcode, parameter);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        //
        // Step 1:
        // - Restore the original registers when retrying.
        // - Resolve the kernel image base.
        // - Allocate executable nonpaged memory for the payload.
        //
        {
            #[expect(non_upper_case_globals)]
            const NonPagedPoolExecute: u64 = 0;

            let vmi = vmi!();

            let attempt = data![retry].begin_attempt(registers!());
            let payload_size = data![payload].bytes.len();

            data![kernel_image_base] = vmi.os().kernel_image_base()?;

            tracing::debug!(attempt, size = payload_size, "allocating shellcode memory");

            inject! {
                nt!ExAllocatePool(
                    NonPagedPoolExecute,            // PoolType
                    payload_size                    // NumberOfBytes
                )
            }
        },
        //
        // Step 2:
        // - Verify the allocation.
        //   - If the allocation fails, retry.
        // - Write the payload into the memory.
        //   - If the write fails, free the allocation and retry.
        //
        {
            let vmi = vmi!();

            let guest_address = Va(vmi.registers().result());
            data![guest_address] = guest_address;

            let attempt = data![retry].attempt;
            let payload = &data![payload];

            if guest_address.is_null() {
                tracing::warn!(attempt, "shellcode allocation failed, retrying");
                return Ok(RecipeControlFlow::Goto(0));
            }

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
                    nt!ExFreePool(guest_address)    // P
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            Ok(RecipeControlFlow::Continue)
        },
    ]
}

/// Builds a kernel-mode shellcode recipe that calls the payload on the
/// hijacked thread.
///
/// Once the shellcode call begins, the shellcode owns the allocation and must
/// release it with `ExFreePool` before returning.
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
///     PVOID Shellcode = ExAllocatePool(NonPagedPoolExecute, PayloadSize);
///
///     if (!Shellcode) {
///         continue;
///     }
///
///     if (!VmiWrite(Shellcode, PayloadBytes, PayloadSize)) {
///         ExFreePool(Shellcode);
///         continue;
///     }
///
///     (Shellcode)(KernelImageBase, Parameter);
///     break;
/// }
/// ```
#[tracing::instrument(name = "kernel_shellcode_call", skip_all)]
pub fn kernel_shellcode_call_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    recipe![
        prepare_kernel_shellcode_recipe::<Driver>(shellcode, parameter),
        //
        // Step 3:
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
                    data![kernel_image_base],       // argument1
                    parameter                       // argument2
                )
            }
        },
    ]
}

/// Builds a kernel-mode shellcode recipe that spawns a system thread for the
/// payload.
///
/// Once `PsCreateSystemThread` succeeds, the shellcode owns the allocation and
/// must release it with `ExFreePool` before returning. The spawned thread
/// terminates by returning from the payload.
///
/// Recoverable failures before thread creation restore the hijacked registers
/// and retry from the allocation step.
///
/// # Payload entry
///
/// `PsCreateSystemThread` passes a single `StartContext` argument, while the
/// payload expects the kernel image base in its first argument and the
/// parameter in its second. A thunk reserved after the payload restores that
/// convention before entering the payload, so a payload built for
/// [`kernel_shellcode_call_recipe`] runs unchanged.
///
/// The thunk is reserved within the payload itself, so the shared steps
/// allocate and write it as part of the payload; only its absolute operands
/// are patched once the allocation address is known. It is never re-entered
/// after the jump, so the payload releasing that allocation remains correct.
///
/// # Execution context
///
/// The spawned thread runs in the System process, not in the hijacked one.
/// An appended parameter block stays valid because it resolves into the
/// payload allocation, while a process-local parameter such as a handle or a
/// user-mode address does not.
///
/// # Equivalent C pseudo-code
///
/// `VmiWrite` represents the host-side write into guest memory.
///
/// ```c
/// for (;;) {
///     PVOID Shellcode = ExAllocatePool(NonPagedPoolExecute, PayloadSize);
///
///     if (!Shellcode) {
///         continue;
///     }
///
///     if (!VmiWrite(Shellcode, PayloadBytes, PayloadSize)) {
///         ExFreePool(Shellcode);
///         continue;
///     }
///
///     PVOID Thunk = (PUCHAR)Shellcode + ThunkOffset;
///
///     if (!VmiWrite(Thunk, ThunkBytes, ThunkLength)) {
///         ExFreePool(Shellcode);
///         continue;
///     }
///
///     HANDLE ThreadHandle;
///
///     NTSTATUS Status = PsCreateSystemThread(&ThreadHandle,
///                                            THREAD_ALL_ACCESS,
///                                            NULL,
///                                            NULL,
///                                            NULL,
///                                            Thunk,
///                                            NULL);
///
///     if (!NT_SUCCESS(Status)) {
///         ExFreePool(Shellcode);
///         continue;
///     }
///
///     ZwClose(ThreadHandle);
///     break;
/// }
/// ```
#[tracing::instrument(name = "kernel_shellcode_spawn", skip_all)]
pub fn kernel_shellcode_spawn_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ShellcodeParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelShellcodeRecipeData>
where
    Driver: VmiMemory<Architecture = Amd64>,
{
    //
    // Reserve the thunk within the payload so the shared steps allocate and
    // write it together with the payload. Its operands are absolute guest
    // values, so they are patched once the allocation address is known.
    //
    let shellcode = shellcode.as_ref();
    let thunk_offset = shellcode.len();

    let mut payload = Vec::with_capacity(thunk_offset + SPAWN_THUNK_LENGTH);
    payload.extend_from_slice(shellcode);
    payload.extend_from_slice(&[0; SPAWN_THUNK_LENGTH]);

    recipe![
        prepare_kernel_shellcode_recipe::<Driver>(payload, parameter),
        //
        // Step 3:
        // - Patch the entry thunk reserved after the payload.
        //   - If the write fails, free the allocation and retry.
        // - Allocate the thread handle slot and create the system thread.
        //
        {
            const THREAD_ALL_ACCESS: u64 = 0x1f_ffff;

            let vmi = vmi!();

            let guest_address = data![guest_address];
            let attempt = data![retry].attempt;
            let parameter = data![payload].parameter_value(guest_address);
            let start_routine = guest_address + thunk_offset as u64;
            let thunk = spawn_thunk(data![kernel_image_base], parameter, guest_address);

            tracing::debug!(
                attempt,
                %start_routine,
                parameter = %Hex(parameter),
                "patching shellcode thunk"
            );

            if let Err(err) = vmi.write(start_routine, &thunk) {
                tracing::warn!(
                    %err,
                    attempt,
                    %start_routine,
                    "shellcode thunk patch failed, retrying"
                );

                inject! {
                    nt!ExFreePool(guest_address)    // P
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            data![thread_handle_ptr] = copy_to_stack!(0u64)?;

            tracing::debug!(
                attempt,
                %start_routine,
                "launching shellcode thread"
            );

            inject! {
                nt!PsCreateSystemThread(
                    data![thread_handle_ptr],       // ThreadHandle
                    THREAD_ALL_ACCESS,              // DesiredAccess
                    0,                              // ObjectAttributes
                    0,                              // ProcessHandle
                    0,                              // ClientId
                    start_routine,                  // StartRoutine
                    0                               // StartContext
                )
            }
        },
        //
        // Step 4:
        // - Verify thread creation.
        //   - If creation fails, free the allocation and retry.
        // - Close the thread handle.
        //
        {
            let vmi = vmi!();

            let status = vmi.registers().result() as u32;
            let attempt = data![retry].attempt;

            if (status as i32) < 0 {
                let guest_address = data![guest_address];

                tracing::warn!(
                    attempt,
                    status = %Hex(status),
                    %guest_address,
                    "shellcode thread creation failed, retrying"
                );

                inject! {
                    nt!ExFreePool(guest_address)    // P
                }?;

                return Ok(RecipeControlFlow::Goto(0));
            }

            let thread_handle = vmi.read_u64(data![thread_handle_ptr])?;

            tracing::debug!(
                thread_handle = %Hex(thread_handle),
                "closing shellcode thread handle"
            );

            inject! {
                nt!ZwClose(thread_handle)           // Handle
            }
        },
    ]
}

/// Length of the thunk reserved after a spawned payload.
const SPAWN_THUNK_LENGTH: usize = 32;

/// Encodes the thunk that restores the payload's two-argument entry.
///
/// `PsCreateSystemThread` enters `StartRoutine` with a single `StartContext`
/// argument in `rcx`, so the thunk loads both payload arguments and jumps to
/// `entry`:
///
/// ```text
/// mov rcx, kernel_image_base
/// mov rdx, parameter
/// mov rax, entry
/// jmp rax
/// ```
///
/// The thunk pushes nothing, so the payload is entered with the stack
/// alignment established by the thread startup call, and the payload's return
/// address remains the one supplied by the kernel thread startup routine.
fn spawn_thunk(kernel_image_base: Va, parameter: u64, entry: Va) -> [u8; SPAWN_THUNK_LENGTH] {
    let mut thunk = [0u8; SPAWN_THUNK_LENGTH];

    // mov rcx, imm64
    thunk[0..2].copy_from_slice(&[0x48, 0xb9]);
    thunk[2..10].copy_from_slice(&kernel_image_base.0.to_le_bytes());

    // mov rdx, imm64
    thunk[10..12].copy_from_slice(&[0x48, 0xba]);
    thunk[12..20].copy_from_slice(&parameter.to_le_bytes());

    // mov rax, imm64
    thunk[20..22].copy_from_slice(&[0x48, 0xb8]);
    thunk[22..30].copy_from_slice(&entry.0.to_le_bytes());

    // jmp rax
    thunk[30..32].copy_from_slice(&[0xff, 0xe0]);

    thunk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_thunk_loads_both_payload_arguments() {
        let thunk = spawn_thunk(
            Va(0xfffff800_01000000),
            0xffffe000_12345678,
            Va(0xffffd000_deadbeef),
        );

        assert_eq!(
            thunk,
            [
                // mov rcx, 0xfffff80001000000
                0x48, 0xb9, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf8, 0xff, 0xff,
                // mov rdx, 0xffffe00012345678
                0x48, 0xba, 0x78, 0x56, 0x34, 0x12, 0x00, 0xe0, 0xff, 0xff,
                // mov rax, 0xffffd000deadbeef
                0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x00, 0xd0, 0xff, 0xff, // jmp rax
                0xff, 0xe0,
            ]
        );
    }
}
