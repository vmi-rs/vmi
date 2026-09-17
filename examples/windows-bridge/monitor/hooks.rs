//! Handles kernel breakpoints installed by the deploy monitor.

#![expect(non_snake_case)]

use vmi::{
    Registers as _, Va, VmiContext, VmiError, VmiEventResponse, VmiVa as _,
    arch::amd64::Amd64,
    driver::VmiFullDriver,
    os::{
        ProcessId, ProcessObject, ThreadObject, VmiOsProcess as _, VmiOsThread as _,
        windows::{WindowsFileObject, WindowsOs, WindowsOsExt as _},
    },
    trace::Hex,
};

use super::{MonitorState, Process, Thread, process_matches_target};
use crate::file_transfer::FileTransfer;

fn record_process_start<Driver>(
    expected_name: &str,
    expected_ppid: ProcessId,
    target_process: &mut Option<ProcessObject>,
    process_object: ProcessObject,
    parent_object: Option<ProcessObject>,
    process: &Process<Driver>,
) where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    let is_target =
        target_process.is_none() && process_matches_target(expected_name, expected_ppid, process);

    if is_target {
        *target_process = Some(process_object);

        tracing::info!(
            name = process.name,
            pid = %process.pid,
            process = %process_object,
            "deployed process started"
        );
    }
    else if let Some(parent_object) = parent_object {
        tracing::debug!(
            name = process.name,
            pid = %process.pid,
            ppid = %process.ppid,
            process = %process_object,
            parent = %parent_object,
        );
    }
    else {
        tracing::debug!(
            name = process.name,
            pid = %process.pid,
            ppid = %process.ppid,
            process = %process_object,
        );
    }
}

/// Handles a `PspInsertProcess` breakpoint and records the process and its parent.
#[tracing::instrument(skip_all)]
pub fn PspInsertProcess<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // NTSTATUS
    // PspInsertProcess (
    //     _In_ PEPROCESS NewProcess,
    //     _In_ PEPROCESS Parent,
    //     _In_ ULONG DesiredAccess,
    //     _In_ ULONG CreateFlags,
    //     ...
    //     );
    //

    let NewProcess = ProcessObject(Va(vmi.os().function_argument(0)?));
    let Parent = ProcessObject(Va(vmi.os().function_argument(1)?));

    tracing::trace!(%NewProcess, %Parent);

    let new_process = vmi.os().process(NewProcess)?;
    let parent = vmi.os().process(Parent)?;

    let process = Process::new(new_process.id()?, parent.id()?, new_process.name()?);
    let process = state.processes.insert_process(NewProcess, process);

    record_process_start(
        &state.expected_name,
        state.expected_ppid,
        &mut state.target_process,
        NewProcess,
        Some(Parent),
        process,
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles an `MmCleanProcessAddressSpace` breakpoint and finalizes the process.
#[tracing::instrument(skip_all)]
pub fn MmCleanProcessAddressSpace<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // VOID
    // MmCleanProcessAddressSpace (
    //     _In_ PEPROCESS Process
    //     );
    //

    let Process = ProcessObject(Va(vmi.os().function_argument(0)?));

    tracing::trace!(%Process);

    let process = match state.processes.mark_process_terminated(Process) {
        Some(process) => process,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    if state.target_process == Some(Process) {
        state.output = Some(Ok(Some(process.pid)));

        tracing::info!(
            name = process.name,
            pid = %process.pid,
            process = %Process,
            "deployed process terminated"
        );
    }
    else {
        tracing::debug!(
            name = process.name,
            pid = %process.pid,
            process = %Process,
        );
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles a `PspInsertThread` breakpoint and records the thread's process.
#[tracing::instrument(skip_all)]
pub fn PspInsertThread<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // VOID
    // PspInsertThread (
    //     _In_ PETHREAD Thread,
    //     _In_ PEPROCESS Process,
    //     ...
    //     );
    //

    let Thread = ThreadObject(Va(vmi.os().function_argument(0)?));
    let Process = ProcessObject(Va(vmi.os().function_argument(1)?));

    tracing::trace!(%Thread, %Process);

    let os_thread = vmi.os().thread(Thread)?;
    let os_process = vmi.os().process(Process)?;

    let tid = os_thread.id()?;
    let pid = os_process.id()?;

    let thread_object = Thread;
    let process_object = Process;
    let thread = Thread::new(tid);
    let mut process_initialized = false;

    let (process, _) = state.processes.try_get_or_insert(
        process_object,
        thread_object,
        || {
            process_initialized = true;
            Ok::<_, VmiError>(Process::new(
                pid,
                os_process.parent_id()?,
                os_process.name()?,
            ))
        },
        || Ok::<_, VmiError>(thread),
    )?;

    if process_initialized {
        record_process_start(
            &state.expected_name,
            state.expected_ppid,
            &mut state.target_process,
            process_object,
            None,
            process,
        );
    }

    tracing::debug!(
        %pid,
        %tid,
        process = %process_object,
        thread = %thread_object,
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles a `KeTerminateThread` breakpoint and finalizes the thread.
#[tracing::instrument(skip_all)]
pub fn KeTerminateThread<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // VOID
    // KeTerminateThread (
    //     _In_ PKTHREAD Thread
    //     );
    //

    let Thread = ThreadObject(Va(vmi.os().function_argument(0)?));

    tracing::trace!(%Thread);

    let os_thread = vmi.os().thread(Thread)?;
    let os_process = os_thread.process()?;

    let tid = os_thread.id()?;
    let pid = os_process.id()?;

    let thread_object = Thread;
    let process_object = os_process.object()?;

    let thread = match state
        .processes
        .mark_thread_terminated(process_object, thread_object)
    {
        Some(thread) => thread,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    tracing::debug!(
        %pid,
        %tid,
        process = %process_object,
        thread = %thread_object,
        transfer_active = thread.file_transfer.is_some(),
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles an `NtWriteFile` breakpoint and marks the file for transfer.
#[tracing::instrument(skip_all)]
pub fn NtWriteFile<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // NTSTATUS
    // NTAPI
    // NtWriteFile(
    //     _In_ HANDLE FileHandle,
    //     _In_opt_ HANDLE Event,
    //     _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    //     _In_opt_ PVOID ApcContext,
    //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    //     _In_reads_bytes_(Length) PVOID Buffer,
    //     _In_ ULONG Length,
    //     _In_opt_ PLARGE_INTEGER ByteOffset,
    //     _In_opt_ PULONG Key
    //     );
    //

    let current_process = vmi.os().current_process()?;
    let process_object = current_process.object()?;

    if state.target_process != Some(process_object) {
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    let FileHandle = vmi.os().function_argument(0)?;

    tracing::trace!(FileHandle = %Hex(FileHandle));

    if vmi.os().is_kernel_handle(FileHandle)? {
        tracing::debug!(handle = %Hex(FileHandle), "kernel handle, skipping");
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    let file_object = match current_process.lookup_object::<WindowsFileObject<_>>(FileHandle)? {
        Some(file_object) => file_object,
        None => {
            tracing::warn!(handle = %Hex(FileHandle), "cannot resolve file handle");
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    let path = file_object.full_path()?;

    let transfer = FileTransfer::new(FileHandle, file_object.va(), path.clone());
    let process = match state.processes.get_process_mut(process_object) {
        Some(process) => process,
        None => {
            tracing::warn!("target process not tracked");
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    if process.mark_file(transfer) {
        tracing::info!(handle = %Hex(FileHandle), path, "marked file for transfer");
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles an `NtClose` breakpoint and starts the file transfer.
#[tracing::instrument(skip_all)]
pub fn NtClose<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    //
    // NTSTATUS
    // NTAPI
    // NtClose (
    //     _In_ _Post_ptr_invalid_ HANDLE Handle
    //     );
    //

    let current_thread = vmi.os().current_thread()?;
    let thread_object = current_thread.object()?;

    if let Some(thread) = state.processes.get_thread(thread_object)
        && thread.file_transfer.is_some()
    {
        return advance_file_transfer(vmi, state, thread_object);
    }

    let current_process = vmi.os().current_process()?;
    let process_object = current_process.object()?;

    if state.target_process != Some(process_object) {
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    if state.processes.get_thread(thread_object).is_none() {
        tracing::warn!(%thread_object, "close on untracked target thread");
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    let Handle = vmi.os().function_argument(0)?;

    tracing::trace!(Handle = %Hex(Handle));

    if vmi.os().is_kernel_handle(Handle)? {
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    // REVIEW: if-let-chain?
    let mut transfer = match state
        .processes
        .get_process_mut(process_object)
        .and_then(|process| process.take_file(Handle))
    {
        Some(transfer) => transfer,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    if let Some(file_object) = current_process.lookup_object::<WindowsFileObject<_>>(Handle)?
        && file_object.va() != transfer.file_object()
    {
        tracing::warn!(
            handle = %Hex(Handle),
            path = transfer.path(),
            "discarding stale file-transfer handle"
        );
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    transfer.start();

    if let Some(thread) = state.processes.get_thread_mut(thread_object) {
        thread.file_transfer = Some(transfer);
    }

    advance_file_transfer(vmi, state, thread_object)
}

/// Advances the `file-transfer` recipe on the current thread.
fn advance_file_transfer<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
    thread_object: ThreadObject,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    let thread = match state.processes.get_thread_mut(thread_object) {
        Some(thread) => thread,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    let file_transfer = match thread.file_transfer.as_mut() {
        Some(file_transfer) => file_transfer,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    let registers = match file_transfer.execute(vmi)? {
        Some(registers) => registers,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    if !file_transfer.done() {
        return Ok(VmiEventResponse::default().with_registers(registers.gp_registers()));
    }

    let file_transfer = match thread.file_transfer.take() {
        Some(file_transfer) => file_transfer,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    tracing::info!(
        path = file_transfer.path(),
        "file-transfer injection completed"
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view())
        .with_registers(registers.gp_registers()))
}
