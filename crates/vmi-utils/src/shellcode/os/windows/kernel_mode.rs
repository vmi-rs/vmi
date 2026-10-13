use vmi_core::{
    Architecture, Registers as _, Va, VmiError,
    driver::VmiMemory,
    os::{ProcessId, ProcessObject, VmiOsImageArchitecture, VmiOsProcess as _},
    trace::Hex,
};
use vmi_os_windows::{
    CLIENT_ID64, KAPC_STATE64, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES64, WindowsOs, WindowsOsExt as _,
};

use super::super::super::{
    ParameterSource,
    arch::ArchAdapter,
    payload::Payload,
    recipe::{RetryPolicy, RetryState},
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

    /// Address of the payload allocation.
    guest_address: Va,

    /// Stack slot where `PsCreateSystemThread` or `ZwCreateThreadEx` stores
    /// the thread handle.
    thread_handle_ptr: Va,

    /// `NTSTATUS` of the last operation.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    status: u32,

    /// Address of the `EPROCESS` structure of the target process.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    process_object: ProcessObject,

    /// Kernel handle of the target process.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    process_handle: u64,

    /// Stack slot where `ZwOpenProcess` stores the process handle.
    ///
    /// The value is then stored in the `process_handle` field.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    process_handle_ptr: Va,

    /// Stack slot where `ZwAllocateVirtualMemory` stores the address of the
    /// new allocation.
    ///
    /// The value is then stored in the `guest_address` field.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    guest_address_ptr: Va,

    /// Stack slot where `KeStackAttachProcess` saves the thread's APC state.
    /// `KeUnstackDetachProcess` restores it from there.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    apc_state_ptr: Va,

    /// Nonpaged pool buffer with a copy of the payload. `MmCopyVirtualMemory`
    /// copies it into the target process.
    ///
    /// # Remarks
    ///
    /// Only [`user_shellcode_spawn_from_kernel_recipe`] uses this field.
    staging_address: Va,
}

impl<Arch> KernelRecipeData<Arch>
where
    Arch: Architecture,
{
    /// Creates recipe data for the given shellcode, parameter and retry policy.
    fn new(
        shellcode: impl AsRef<[u8]>,
        parameter: impl ParameterSource,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            payload: Payload::new(shellcode, parameter),
            retry: RetryState::new(retry),
            guest_address: Va::null(),
            thread_handle_ptr: Va::null(),
            status: 0,
            process_object: ProcessObject(Va::null()),
            process_handle: 0,
            process_handle_ptr: Va::null(),
            guest_address_ptr: Va::null(),
            apc_state_ptr: Va::null(),
            staging_address: Va::null(),
        }
    }
}

/// Returns whether an `NTSTATUS` reports success or information.
#[expect(non_snake_case)]
fn NT_SUCCESS(status: u32) -> bool {
    (status as i32) >= 0
}

/// Builds the steps shared by every kernel-mode shellcode recipe.
fn prepare_kernel_shellcode_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
    retry: RetryPolicy,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    let data = KernelRecipeData::<Driver::Architecture>::new(shellcode, parameter, retry);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        //
        // Step 1:
        // - Restore the original registers when retrying.
        //   - If the retry policy allows no further attempt, return an error.
        // - Allocate executable nonpaged memory for the payload.
        //
        {
            #[expect(non_upper_case_globals)]
            const NonPagedPoolExecute: u64 = 0;

            let attempt = data![retry].begin_attempt(registers!())?;
            let payload_size = data![payload].bytes.len();

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

            let attempt = data![retry].attempt();
            let payload = &data![payload];

            if guest_address.is_null() {
                tracing::warn!(attempt, "shellcode allocation failed");
                data![retry].abort_attempt();
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
                    "shellcode write failed"
                );

                data![retry].abort_attempt();

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
/// restores the original registers and retries from the allocation step, as
/// long as the `retry` policy allows. Otherwise, the recipe returns an error.
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
    retry: RetryPolicy,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    recipe![
        prepare_kernel_shellcode_recipe::<Driver>(shellcode, parameter, retry),
        //
        // Step 3:
        // - Resolve the parameter and call the shellcode.
        //
        {
            let vmi = vmi!();

            let guest_address = data![guest_address];
            let attempt = data![retry].attempt();
            let parameter = data![payload].parameter_value(guest_address);
            let kernel_image_base = vmi.os().kernel_image_base()?;

            tracing::debug!(
                attempt,
                %guest_address,
                parameter = %Hex(parameter),
                "invoking shellcode"
            );

            inject! {
                guest_address(
                    kernel_image_base,              // argument1
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
/// restores the original registers and retries from the allocation step, as
/// long as the `retry` policy allows. Otherwise, the recipe returns an error.
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
    retry: RetryPolicy,
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
        prepare_kernel_shellcode_recipe::<Driver>(payload, parameter, retry),
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
            let attempt = data![retry].attempt();
            let parameter = data![payload].parameter_value(guest_address);
            let kernel_image_base = vmi.os().kernel_image_base()?;

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
                    "shellcode thunk patch failed"
                );

                data![retry].abort_attempt();

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
            let attempt = data![retry].attempt();

            if !NT_SUCCESS(status) {
                let guest_address = data![guest_address];

                tracing::warn!(
                    attempt,
                    status = %Hex(status),
                    %guest_address,
                    "shellcode thread creation failed"
                );

                data![retry].abort_attempt();

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

/// Index of the recipe step that frees the user-mode allocation after a
/// failure.
const STEP_FREE_ALLOCATION: usize = 11;

/// Index of the recipe step that closes the process handle after a failure.
const STEP_CLOSE_PROCESS: usize = 12;

/// Builds a kernel-mode recipe that spawns a user-mode thread for the payload
/// in the process that `pid` identifies.
///
/// The recipe allocates executable memory in the target process, stages the
/// payload in nonpaged pool and copies it over, then starts the payload on a
/// new thread of the target process with `ZwCreateThreadEx`. Windows builds
/// the new thread's frames, and the payload receives the parameter in its first
/// argument, as with
/// [`user_shellcode_spawn_recipe`](super::user_mode::user_shellcode_spawn_recipe).
///
/// The recipe allocates the memory while the hijacked thread is attached to the
/// `System` process. Windows checks Arbitrary Code Guard against the caller's
/// current process, not the target, and the hijacked thread's own process may
/// prohibit dynamic code.
///
/// Once `ZwCreateThreadEx` succeeds, the shellcode owns the allocation and must
/// release it with `VirtualFree` before returning.
///
/// If a recoverable error occurs before the thread is created, the recipe
/// frees what it allocated, restores the original registers and retries from
/// the first step, as long as the `retry` policy allows. Otherwise, the recipe
/// returns an error.
///
/// # Equivalent C pseudo-code
///
/// `VmiWrite` represents the host-side write into guest memory.
///
/// ```c
/// for (;;) {
///     HANDLE ProcessHandle;
///     NTSTATUS Status = ZwOpenProcess(&ProcessHandle,
///                                     PROCESS_ALL_ACCESS,
///                                     &KernelHandleAttributes,
///                                     &ClientId);
///
///     if (!NT_SUCCESS(Status)) {
///         return Status;
///     }
///
///     KAPC_STATE ApcState;
///     KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
///
///     PVOID Shellcode = NULL;
///     SIZE_T RegionSize = PayloadSize;
///     Status = ZwAllocateVirtualMemory(ProcessHandle,
///                                      &Shellcode,
///                                      0,
///                                      &RegionSize,
///                                      MEM_COMMIT | MEM_RESERVE,
///                                      PAGE_EXECUTE_READWRITE);
///
///     KeUnstackDetachProcess(&ApcState);
///
///     if (!NT_SUCCESS(Status)) {
///         ZwClose(ProcessHandle);
///         continue;
///     }
///
///     PVOID Staging = ExAllocatePool(NonPagedPool, PayloadSize);
///
///     if (!Staging || !VmiWrite(Staging, PayloadBytes, PayloadSize)) {
///         if (Staging) {
///             ExFreePool(Staging);
///         }
///
///         ZwFreeVirtualMemory(ProcessHandle, &Shellcode, &Zero, MEM_RELEASE);
///         ZwClose(ProcessHandle);
///         continue;
///     }
///
///     SIZE_T NumberOfBytesCopied;
///     Status = MmCopyVirtualMemory(CurrentProcess,
///                                  Staging,
///                                  Process,
///                                  Shellcode,
///                                  PayloadSize,
///                                  KernelMode,
///                                  &NumberOfBytesCopied);
///
///     ExFreePool(Staging);
///
///     HANDLE ThreadHandle;
///
///     if (NT_SUCCESS(Status)) {
///         Status = ZwCreateThreadEx(&ThreadHandle,
///                                   THREAD_ALL_ACCESS,
///                                   &KernelHandleAttributes,
///                                   ProcessHandle,
///                                   Shellcode,
///                                   Parameter,
///                                   0,
///                                   0,
///                                   0,
///                                   0,
///                                   NULL);
///     }
///
///     if (!NT_SUCCESS(Status)) {
///         ZwFreeVirtualMemory(ProcessHandle, &Shellcode, &Zero, MEM_RELEASE);
///         ZwClose(ProcessHandle);
///         continue;
///     }
///
///     ZwClose(ThreadHandle);
///     ZwClose(ProcessHandle);
///     break;
/// }
/// ```
///
/// # Notes
///
/// The recipe refuses a 32-bit (WoW64) process. ntoskrnl does not export
/// `ZwCreateThreadEx`, so the recipe takes its address from the kernel profile
/// and returns an error when the profile lacks it.
#[tracing::instrument(name = "user_shellcode_spawn_from_kernel", skip_all)]
pub fn user_shellcode_spawn_from_kernel_recipe<Driver>(
    shellcode: impl AsRef<[u8]>,
    parameter: impl ParameterSource,
    retry: RetryPolicy,
    pid: ProcessId,
) -> Recipe<WindowsOs<Driver>, KernelRecipeData<Driver::Architecture>>
where
    Driver: VmiMemory,
    Driver::Architecture: InjectorArchAdapter<Driver> + vmi_os_windows::ArchAdapter<Driver>,
    WindowsOs<Driver>: InjectorOsAdapter<Architecture = Driver::Architecture, Driver = Driver>,
{
    let data = KernelRecipeData::<Driver::Architecture>::new(shellcode, parameter, retry);

    recipe![
        Recipe::<WindowsOs<Driver>>::new(data),
        //
        // Step 1:
        // - Restore the original registers when retrying.
        //   - If the retry policy allows no further attempt, return an error.
        // - Find the target process and refuse a 32-bit one.
        // - Open the target process with a kernel handle.
        //
        {
            const PROCESS_ALL_ACCESS: u64 = 0x1f_ffff;

            let vmi = vmi!();
            let symbols = vmi.os().symbols();

            let attempt = data![retry].begin_attempt(registers!())?;

            if symbols.ZwCreateThreadEx.is_none() {
                return Err(VmiError::Other("ZwCreateThreadEx not found"));
            }

            let target = match vmi.os().find_process(pid)? {
                Some(target) => target,
                None => return Err(VmiError::Other("target process not found")),
            };

            if target.architecture()? != VmiOsImageArchitecture::Amd64 {
                return Err(VmiError::Other(
                    "spawning into 32-bit processes is not supported",
                ));
            }

            data![process_object] = target.object()?;

            let object_attributes = copy_to_stack!(OBJECT_ATTRIBUTES64::new(OBJ_KERNEL_HANDLE))?;
            let client_id = copy_to_stack!(CLIENT_ID64::process(pid))?;
            data![process_handle_ptr] = copy_to_stack!(0u64)?;

            tracing::debug!(attempt, %pid, "opening the target process");

            inject! {
                nt!ZwOpenProcess(
                    data![process_handle_ptr],      // ProcessHandle
                    PROCESS_ALL_ACCESS,             // DesiredAccess
                    object_attributes,              // ObjectAttributes
                    client_id                       // ClientId
                )
            }
        },
        //
        // Step 2:
        // - Verify the process handle.
        //   - If the process cannot be opened, return an error.
        // - Attach to the `System` process for the allocation in step 3.
        //
        //   Windows checks Arbitrary Code Guard (ACG) against the caller's
        //   current process (`KTHREAD.ApcState.Process`), which
        //   `NtAllocateVirtualMemory` saves before it attaches to the target,
        //   and never against the target. Without the attach, the check would
        //   test the hijacked thread's own process. If that process prohibits
        //   dynamic code, as some svchost.exe instances on Windows 11 do, the
        //   allocation would fail with `STATUS_DYNAMIC_CODE_BLOCKED`
        //   (0xC0000604) whatever the target. `System` does not prohibit
        //   dynamic code. Attaching to the target instead would apply the
        //   target's own ACG, which refuses an allocation in services.exe.
        //
        //   While attached, the hijacked thread's own user address space is not
        //   mapped. The process handle is a kernel handle, and the pointers
        //   that step 3 passes point to the kernel stack, so both stay valid.
        //
        {
            let vmi = vmi!();

            let status = vmi.registers().result() as u32;

            if !NT_SUCCESS(status) {
                tracing::warn!(status = %Hex(status), %pid, "opening the target process failed");
                return Err(VmiError::Other("the target process could not be opened"));
            }

            data![process_handle] = vmi.read_u64(data![process_handle_ptr])?;

            let system_process = vmi.os().system_process()?.object()?;
            data![apc_state_ptr] = copy_to_stack!(KAPC_STATE64::new())?;

            inject! {
                nt!KeStackAttachProcess(
                    system_process,                 // PROCESS
                    data![apc_state_ptr]            // ApcState
                )
            }
        },
        //
        // Step 3:
        // - Allocate executable memory in the target process.
        //
        {
            const MEM_COMMIT: u64 = 0x1000;
            const MEM_RESERVE: u64 = 0x2000;
            const PAGE_EXECUTE_READWRITE: u64 = 0x40;

            let attempt = data![retry].attempt();
            let payload_size = data![payload].bytes.len() as u64;

            data![guest_address_ptr] = copy_to_stack!(0u64)?;
            let size_ptr = copy_to_stack!(payload_size)?;

            tracing::debug!(attempt, size = payload_size, "allocating shellcode memory");

            inject! {
                nt!ZwAllocateVirtualMemory(
                    data![process_handle],          // ProcessHandle
                    data![guest_address_ptr],       // BaseAddress
                    0,                              // ZeroBits
                    size_ptr,                       // RegionSize
                    MEM_COMMIT | MEM_RESERVE,       // AllocationType
                    PAGE_EXECUTE_READWRITE          // Protect
                )
            }
        },
        //
        // Step 4:
        // - Keep the allocation's status, because the detach overwrites the
        //   result register.
        // - Detach from the `System` process, also after a failed allocation.
        //
        {
            data![status] = vmi!().registers().result() as u32;

            inject! {
                nt!KeUnstackDetachProcess(
                    data![apc_state_ptr]            // ApcState
                )
            }
        },
        //
        // Step 5:
        // - Verify the allocation.
        //   - If the allocation fails, close the process handle and retry.
        // - Allocate the nonpaged staging buffer.
        //
        {
            #[expect(non_upper_case_globals)]
            const NonPagedPool: u64 = 0;

            let vmi = vmi!();

            let status = data![status];
            let attempt = data![retry].attempt();

            if !NT_SUCCESS(status) {
                tracing::warn!(attempt, status = %Hex(status), "shellcode allocation failed");
                data![retry].abort_attempt();
                return Ok(RecipeControlFlow::Goto(STEP_CLOSE_PROCESS));
            }

            data![guest_address] = Va(vmi.read_u64(data![guest_address_ptr])?);

            let payload_size = data![payload].bytes.len();

            tracing::debug!(
                attempt,
                guest_address = %data![guest_address],
                size = payload_size,
                "allocating the staging buffer"
            );

            inject! {
                nt!ExAllocatePool(
                    NonPagedPool,                   // PoolType
                    payload_size                    // NumberOfBytes
                )
            }
        },
        //
        // Step 6:
        // - Verify the staging buffer.
        //   - If the allocation fails, free the user-mode allocation and retry.
        // - Write the payload into the staging buffer.
        //   - If the write fails, free both allocations and retry.
        // - Copy the payload into the target process.
        //
        {
            #[expect(non_upper_case_globals)]
            const KernelMode: u64 = 0;

            let vmi = vmi!();

            let staging_address = Va(vmi.registers().result());
            data![staging_address] = staging_address;

            let attempt = data![retry].attempt();

            if staging_address.is_null() {
                tracing::warn!(attempt, "staging buffer allocation failed");
                data![retry].abort_attempt();
                return Ok(RecipeControlFlow::Goto(STEP_FREE_ALLOCATION));
            }

            if let Err(err) = vmi.write(staging_address, &data![payload].bytes) {
                tracing::warn!(
                    %err,
                    attempt,
                    %staging_address,
                    "shellcode write failed"
                );

                data![retry].abort_attempt();

                inject! {
                    nt!ExFreePool(staging_address)  // P
                }?;

                return Ok(RecipeControlFlow::Goto(STEP_FREE_ALLOCATION));
            }

            let current_process = vmi.os().current_process()?.object()?;
            let guest_address = data![guest_address];
            let payload_size = data![payload].bytes.len();
            let number_of_bytes_copied_ptr = copy_to_stack!(0u64)?;

            tracing::debug!(
                attempt,
                %staging_address,
                %guest_address,
                size = payload_size,
                "copying shellcode"
            );

            inject! {
                nt!MmCopyVirtualMemory(
                    current_process,                // FromProcess
                    staging_address,                // FromAddress
                    data![process_object],          // ToProcess
                    guest_address,                  // ToAddress
                    payload_size,                   // BufferSize
                    KernelMode,                     // PreviousMode
                    number_of_bytes_copied_ptr      // NumberOfBytesCopied
                )
            }
        },
        //
        // Step 7:
        // - Free the staging buffer.
        //   - If the copy failed, free the user-mode allocation afterwards and
        //     retry.
        //
        {
            let status = vmi!().registers().result() as u32;
            let attempt = data![retry].attempt();
            let staging_address = data![staging_address];

            if !NT_SUCCESS(status) {
                tracing::warn!(attempt, status = %Hex(status), "shellcode copy failed");

                data![retry].abort_attempt();

                inject! {
                    nt!ExFreePool(staging_address)  // P
                }?;

                return Ok(RecipeControlFlow::Goto(STEP_FREE_ALLOCATION));
            }

            inject! {
                nt!ExFreePool(staging_address)      // P
            }
        },
        //
        // Step 8:
        // - Create the shellcode thread in the target process through
        //   `ZwCreateThreadEx`, which ntoskrnl does not export.
        //
        {
            const THREAD_ALL_ACCESS: u64 = 0x1f_ffff;

            let vmi = vmi!();
            let symbols = vmi.os().symbols();

            #[expect(non_snake_case)]
            let ZwCreateThreadEx = match symbols.ZwCreateThreadEx {
                Some(rva) => vmi.os().kernel_image_base()? + rva,
                None => return Err(VmiError::Other("ZwCreateThreadEx not found")),
            };

            let attempt = data![retry].attempt();
            let guest_address = data![guest_address];
            let parameter = data![payload].parameter_value(guest_address);

            let object_attributes = copy_to_stack!(OBJECT_ATTRIBUTES64::new(OBJ_KERNEL_HANDLE))?;
            data![thread_handle_ptr] = copy_to_stack!(0u64)?;

            tracing::debug!(
                attempt,
                start_address = %guest_address,
                parameter = %Hex(parameter),
                "launching shellcode thread"
            );

            inject! {
                ZwCreateThreadEx(
                    data![thread_handle_ptr],       // ThreadHandle
                    THREAD_ALL_ACCESS,              // DesiredAccess
                    object_attributes,              // ObjectAttributes
                    data![process_handle],          // ProcessHandle
                    guest_address,                  // StartRoutine
                    parameter,                      // Argument
                    0,                              // CreateFlags
                    0,                              // ZeroBits
                    0,                              // StackSize
                    0,                              // MaximumStackSize
                    0                               // AttributeList
                )
            }
        },
        //
        // Step 9:
        // - Verify thread creation.
        //   - If creation fails, free the user-mode allocation and retry.
        // - Close the thread handle.
        //
        {
            let vmi = vmi!();

            let status = vmi.registers().result() as u32;
            let attempt = data![retry].attempt();

            if !NT_SUCCESS(status) {
                tracing::warn!(
                    attempt,
                    status = %Hex(status),
                    guest_address = %data![guest_address],
                    "shellcode thread creation failed"
                );

                data![retry].abort_attempt();
                return Ok(RecipeControlFlow::Goto(STEP_FREE_ALLOCATION));
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
        //
        // Step 10:
        // - Close the process handle.
        //
        {
            inject! {
                nt!ZwClose(data![process_handle])   // Handle
            }
        },
        //
        // Step 11:
        // - Finish the recipe, so that the failure steps below do not run.
        //
        {
            tracing::debug!(
                %pid,
                start_address = %data![guest_address],
                "shellcode thread created"
            );

            Ok(RecipeControlFlow::Break)
        },
        //
        // Step 12 (`STEP_FREE_ALLOCATION`):
        // - Free the user-mode allocation after a failure.
        //
        {
            const MEM_RELEASE: u64 = 0x8000;

            let address_ptr = copy_to_stack!(data![guest_address].0)?;
            let size_ptr = copy_to_stack!(0u64)?;

            inject! {
                nt!ZwFreeVirtualMemory(
                    data![process_handle],          // ProcessHandle
                    address_ptr,                    // BaseAddress
                    size_ptr,                       // RegionSize
                    MEM_RELEASE                     // FreeType
                )
            }
        },
        //
        // Step 13 (`STEP_CLOSE_PROCESS`):
        // - Close the process handle after a failure and retry.
        //
        {
            inject! {
                nt!ZwClose(data![process_handle])   // Handle
            }?;

            Ok(RecipeControlFlow::Goto(0))
        },
    ]
}
