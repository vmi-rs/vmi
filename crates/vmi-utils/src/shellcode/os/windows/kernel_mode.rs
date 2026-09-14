use vmi_core::{Architecture, Registers as _, Va, driver::VmiMemory, trace::Hex};
use vmi_os_windows::WindowsOs;

use super::super::super::{
    ParameterSource, arch::ArchAdapter, payload::Payload, recipe::RetryState,
};
use crate::injector::{
    ArchAdapter as InjectorArchAdapter, OsAdapter as InjectorOsAdapter, Recipe, RecipeControlFlow,
    recipe,
};

/// Data retained while the kernel-mode shellcode recipe executes.
#[derive(Debug)]
pub struct KernelRecipeData<Arch>
where
    Arch: Architecture,
{
    /// Shellcode payload. Contains the shellcode and the parameters.
    payload: Payload,

    /// Retry state for the shellcode execution.
    retry: RetryState<Arch>,

    /// Kernel image base address.
    kernel_image_base: Va,

    /// Guest virtual address of the payload allocation.
    guest_address: Va,

    /// Guest virtual address of the stack slot that receives the thread handle.
    thread_handle_ptr: Va,
}

impl<Arch> KernelRecipeData<Arch>
where
    Arch: Architecture,
{
    /// Creates recipe data for the given shellcode and parameter.
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ParameterSource) -> Self {
        Self {
            payload: Payload::new(shellcode, parameter),
            retry: RetryState::default(),
            kernel_image_base: Va::null(),
            guest_address: Va::null(),
            thread_handle_ptr: Va::null(),
        }
    }
}

/// Builds the steps shared by every kernel-mode shellcode recipe.
fn prepare_kernel_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    let data = KernelRecipeData::<Driver::Architecture>::new(shellcode, parameter);

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
/// If a recoverable error occurs before the shellcode is called, the recipe
/// restores the original registers and retries from the allocation step.
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
    parameter: impl ParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
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
/// must release it with `ExFreePool` before returning.
///
/// If a recoverable error occurs before the thread is created, the recipe
/// restores the original registers and retries from the allocation step.
///
/// # Payload entry
///
/// `PsCreateSystemThread` passes a single `StartContext` argument, while the
/// payload expects the kernel image base in its first argument and the
/// parameter in its second. A thunk loads these arguments and jumps to the
/// payload. This lets payloads written for [`kernel_shellcode_call_recipe`]
/// run without changes.
///
/// The thunk is stored immediately after the shellcode in the same allocation.
/// Any parameter data is appended after the thunk. Its final bytes are written
/// once the allocation address is known.
///
/// # Execution context
///
/// The spawned thread runs in the `System` process.
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
    parameter: impl ParameterSource,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    Driver::Architecture: ArchAdapter + InjectorArchAdapter<Driver>,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    // Reserve space for the thunk in the payload.
    // Fill in its addresses after the allocation address is known.
    let shellcode = shellcode.as_ref();
    let thunk_offset = shellcode.len();
    let thunk_size = size_of::<<Driver::Architecture as ArchAdapter>::Thunk>();

    let mut payload = Vec::with_capacity(thunk_offset + thunk_size);
    payload.extend_from_slice(shellcode);
    payload.resize(thunk_offset + thunk_size, 0);

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
            let kernel_image_base = data![kernel_image_base];

            let start_routine = guest_address + thunk_offset as u64;
            let thunk =
                Driver::Architecture::encode_thunk(guest_address, kernel_image_base, parameter);

            tracing::debug!(
                attempt,
                %start_routine,
                parameter = %Hex(parameter),
                "patching shellcode thunk"
            );

            if let Err(err) = vmi.write(start_routine, thunk.as_ref()) {
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
            #[expect(non_snake_case)]
            fn NT_SUCCESS(status: u32) -> bool {
                (status as i32) >= 0
            }

            let vmi = vmi!();

            let status = vmi.registers().result() as u32;
            let attempt = data![retry].attempt;

            if !NT_SUCCESS(status) {
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
