#![expect(non_snake_case)]

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
};

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

use super::{MonitorState, Process, Thread};
use crate::file_transfer::FileTransfer;

/// Kernel breakpoint callback.
type MonitorCallback<Driver> = fn(
    &VmiContext<WindowsOs<Driver>>,
    &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>;

/// Named kernel breakpoint handler.
///
/// Each name must identify exactly one callback. Tags compare and hash by name.
pub struct MonitorHook<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Symbol name used for diagnostics and tag identity.
    pub name: &'static str,

    /// Handler invoked when the breakpoint fires.
    pub callback: MonitorCallback<Driver>,
}

impl<Driver> Debug for MonitorHook<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

impl<Driver> Clone for MonitorHook<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Driver> Copy for MonitorHook<Driver> where Driver: VmiFullDriver<Architecture = Amd64> {}

impl<Driver> PartialEq for MonitorHook<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(other.name)
    }
}

impl<Driver> Eq for MonitorHook<Driver> where Driver: VmiFullDriver<Architecture = Amd64> {}

impl<Driver> Hash for MonitorHook<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

/// Handles a `PspInsertProcess` breakpoint.
///
/// Checks whether the new process was created by the thread we expected. If so,
/// selects it as the program to watch. Records the process and its parent ID.
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

    tracing::debug!(
        name = process.name,
        pid = %process.pid,
        ppid = %process.ppid,
        process = %NewProcess,
        parent = %Parent,
    );

    // Check if the current thread is the creator thread.
    if state.target_process.is_none()
        && let Some(creator_thread) = state.creator_thread
        && vmi.os().current_thread()?.object()? == creator_thread
    {
        state.target_process = Some(NewProcess);
        state.creator_thread = None;

        tracing::info!(
            name = process.name,
            pid = %process.pid,
            process = %NewProcess,
            "deployed process started"
        );
    }

    state.tracker.insert_process(NewProcess, process);

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles an `MmCleanProcessAddressSpace` breakpoint.
///
/// Retires the process while retaining its context for later events. If it is our
/// program, saves its process ID as the result and marks the run as finished.
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

    let process = match state.tracker.retire_process(Process) {
        Some(process) => process,
        None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
    };

    tracing::debug!(
        name = process.name,
        pid = %process.pid,
        process = %Process,
    );

    if state.target_process == Some(Process) {
        state.output = Some(Ok(Some(process.pid)));

        tracing::info!(
            name = process.name,
            pid = %process.pid,
            process = %Process,
            "deployed process terminated"
        );
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles a `PspInsertThread` breakpoint.
///
/// Replaces the new thread's context and preserves existing process context.
/// Records its process if that process is not yet known to the monitor.
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

    state.tracker.try_insert_thread(
        process_object,
        thread_object,
        || {
            Ok::<_, VmiError>(Process::new(
                pid,
                os_process.parent_id()?,
                os_process.name()?,
            ))
        },
        Thread::new(tid),
    )?;

    tracing::debug!(
        %pid,
        %tid,
        process = %process_object,
        thread = %thread_object,
    );

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles a `KeTerminateThread` breakpoint.
///
/// Clears the expected creator reference when that thread terminates. Retires
/// the thread's record while retaining its context for later events.
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

    // Clear `creator_thread` so a reused thread object cannot be mistaken for
    // the expected creating thread. Do this before tracker retirement, since
    // the deploy thread may have been created before tracking began.
    if state.creator_thread == Some(Thread) {
        state.creator_thread = None;
    }

    tracing::trace!(%Thread);

    let os_thread = vmi.os().thread(Thread)?;
    let os_process = os_thread.process()?;

    let tid = os_thread.id()?;
    let pid = os_process.id()?;

    let thread_object = Thread;
    let process_object = os_process.object()?;

    let thread = match state.tracker.retire_thread(process_object, thread_object) {
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

/// Handles an `NtWriteFile` breakpoint.
///
/// Keeps a list of files that our program tries to write. The `NtClose` handler
/// uses this list to decide which files to copy out of the Windows VM.
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

    let process = match state.tracker.get_process_mut(process_object) {
        Some(process) => process,
        None => {
            tracing::warn!("target process not tracked");
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    let file_object = match current_process.lookup_object::<WindowsFileObject<_>>(FileHandle)? {
        Some(file_object) => file_object,
        None => {
            tracing::warn!(handle = %Hex(FileHandle), "cannot resolve file handle");
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
    };

    let path = file_object.full_path()?;
    let transfer = FileTransfer::new(FileHandle, file_object.va(), path.clone());

    if process.record_file_transfer(transfer) {
        tracing::info!(handle = %Hex(FileHandle), path, "recorded file transfer");
    }

    Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
}

/// Handles an `NtClose` breakpoint.
///
/// Starts copying a file when our program closes a handle recorded by the
/// `NtWriteFile` handler. Later calls on the same thread run the next steps of
/// the copy.
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

    if let Some(thread) = state.tracker.get_thread(thread_object)
        && thread.file_transfer.is_some()
    {
        return advance_file_transfer(vmi, state, thread_object);
    }

    // (equivalent to `vmi.os().current_process()?`)
    let current_process = current_thread.current_process()?;
    let process_object = current_process.object()?;

    if state.target_process != Some(process_object) {
        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
    }

    if !state.tracker.contains_thread(thread_object) {
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
        .tracker
        .get_process_mut(process_object)
        .and_then(|process| process.take_file_transfer(Handle))
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

    if let Some(thread) = state.tracker.get_thread_mut(thread_object) {
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
    let thread = match state.tracker.get_thread_mut(thread_object) {
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
