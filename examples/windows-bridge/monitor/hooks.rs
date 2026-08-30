//! Kernel breakpoint handlers installed by `Monitor::new`, one per hooked function.

#![expect(non_snake_case)]

use vmi::{
    Registers as _, Va, VmiContext, VmiError, VmiEventResponse, VmiVa as _,
    arch::amd64::Amd64,
    driver::VmiFullDriver,
    os::{
        ProcessObject, ThreadObject, VmiOsProcess as _, VmiOsThread as _,
        windows::{WindowsFileObject, WindowsOs, WindowsOsExt as _},
    },
    trace::Hex,
};

use super::{MonitorState, Process, Thread, process_matches_target};
use crate::file_transfer::FileTransfer;

/// Hooks process creation to record the new process and its parent.
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
    let new_process = vmi.os().process(NewProcess)?;
    let parent = vmi.os().process(Parent)?;
    let process = Process {
        pid: new_process.id()?,
        ppid: parent.id()?,
        name: new_process.name()?,
        terminated: false,
        file_transfers: Default::default(),
    };
    let is_target = state.target_process.is_none()
        && process_matches_target(&state.expected_name, state.expected_ppid, &process);

    tracing::info!(
        hook = "PspInsertProcess",
        process = %NewProcess,
        pid = %process.pid,
        name = %process.name,
        parent = %Parent,
        ppid = %process.ppid,
        "kernel function called"
    );

    state.processes.insert_process(NewProcess, process);

    if is_target {
        state.target_process = Some(NewProcess);
        let process = state
            .processes
            .get_process(NewProcess)
            .expect("inserted process");
        tracing::info!(
            process = %NewProcess,
            pid = %process.pid,
            name = %process.name,
            "deployed process started"
        );
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Hooks address-space cleanup to finalize a terminated process.
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
    let thread_objects = state.processes.threads_of(Process).collect::<Vec<_>>();
    for thread_object in thread_objects {
        state
            .processes
            .get_thread_mut(thread_object)
            .expect("process thread index is consistent")
            .mark_terminated();
    }
    let process = match state.processes.get_process_mut(Process) {
        Some(process) => process,
        None => {
            tracing::info!(
                hook = "MmCleanProcessAddressSpace",
                process = %Process,
                tracked = false,
                "kernel function called"
            );
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    process.mark_terminated();
    tracing::info!(
        hook = "MmCleanProcessAddressSpace",
        process = %Process,
        pid = %process.pid,
        name = %process.name,
        terminated = process.terminated,
        tracked = true,
        "kernel function called"
    );

    if state.target_process == Some(Process) {
        state.completion = Some(Ok(Some(process.pid)));
        tracing::info!(
            process = %Process,
            pid = %process.pid,
            "deployed process terminated"
        );
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Hooks thread creation to record the new thread's owning process.
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

    let thread_object = ThreadObject(Va(vmi.os().function_argument(0)?));
    let process_object = ProcessObject(Va(vmi.os().function_argument(1)?));
    let thread = Thread {
        tid: vmi.os().thread(thread_object)?.id()?,
        terminated: false,
        file_transfer: None,
    };
    let tid = thread.tid;

    if state
        .processes
        .insert_thread(process_object, thread_object, thread)
        .is_err()
    {
        tracing::info!(
            hook = "PspInsertThread",
            thread = %thread_object,
            %tid,
            process = %process_object,
            tracked = false,
            "kernel function called"
        );
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    tracing::info!(
        hook = "PspInsertThread",
        thread = %thread_object,
        %tid,
        process = %process_object,
        tracked = true,
        "kernel function called"
    );
    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Hooks thread termination to finalize a terminated thread.
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

    let thread_object = ThreadObject(Va(vmi.os().function_argument(0)?));
    let process_object = state.processes.process_of(thread_object);
    let thread = match state.processes.get_thread_mut(thread_object) {
        Some(thread) => thread,
        None => {
            tracing::info!(
                hook = "KeTerminateThread",
                thread = %thread_object,
                tracked = false,
                "kernel function called"
            );
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    thread.mark_terminated();
    tracing::info!(
        hook = "KeTerminateThread",
        thread = %thread_object,
        tid = %thread.tid,
        process = ?process_object,
        terminated = thread.terminated,
        transfer_active = thread.file_transfer.is_some(),
        tracked = true,
        "kernel function called"
    );
    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Hooks a synchronous `NtWriteFile` to mark its target file for transfer.
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
    if vmi.os().is_kernel_handle(FileHandle)? {
        tracing::trace!(handle = %Hex(FileHandle), "ignoring kernel file handle");
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
    let process_id = state
        .processes
        .get_process(process_object)
        .expect("target process is tracked")
        .pid;
    let transfer = FileTransfer::new(FileHandle, file_object.va(), path.clone());
    state
        .processes
        .get_process_mut(process_object)
        .expect("target process is tracked")
        .mark_file(transfer);

    tracing::info!(
        hook = "NtWriteFile",
        process = %process_object,
        pid = %process_id,
        handle = %Hex(FileHandle),
        path,
        "marked file for transfer"
    );
    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Hooks `NtClose` to start a marked file's transfer before its handle closes.
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

    let thread_object = vmi.os().current_thread()?.object()?;
    if state
        .processes
        .get_thread(thread_object)
        .is_some_and(|thread| thread.file_transfer.is_some())
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
    if vmi.os().is_kernel_handle(Handle)? {
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    let mut transfer = match state
        .processes
        .get_process_mut(process_object)
        .expect("target process is tracked")
        .take_file(Handle)
    {
        Some(transfer) => transfer,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    let resolved = current_process.lookup_object::<WindowsFileObject<_>>(Handle)?;
    if !resolved.is_some_and(|file_object| file_object.va() == transfer.file_object()) {
        tracing::warn!(
            handle = %Hex(Handle),
            path = transfer.path(),
            "discarding stale file-transfer handle"
        );
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    transfer.start();
    state
        .processes
        .get_thread_mut(thread_object)
        .expect("target thread checked above")
        .file_transfer = Some(transfer);
    advance_file_transfer(vmi, state, thread_object)
}

/// Advances a thread's in-progress file transfer by one recipe step.
fn advance_file_transfer<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
    state: &mut MonitorState<Driver>,
    thread_object: ThreadObject,
) -> Result<VmiEventResponse<Amd64>, VmiError>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    let thread = state
        .processes
        .get_thread_mut(thread_object)
        .expect("active transfer thread is tracked");
    let transfer = thread
        .file_transfer
        .as_mut()
        .expect("active transfer thread has a transfer");
    let registers = match transfer.execute(vmi)? {
        Some(registers) => registers,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    if !transfer.done() {
        return Ok(VmiEventResponse::default().with_registers(registers.gp_registers()));
    }

    let transfer = thread
        .file_transfer
        .take()
        .expect("completed transfer remains attached to thread");
    tracing::info!(
        thread = %thread_object,
        tid = %thread.tid,
        path = transfer.path(),
        "file-transfer injection completed"
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view())
        .with_registers(registers.gp_registers()))
}
