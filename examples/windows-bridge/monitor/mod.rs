mod tracker;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use isr::{Profile, macros::symbols};
use vmi::{
    MemoryAccess, Registers as _, Va, VcpuId, View, VmiContext, VmiError, VmiEventResponse,
    VmiHandler, VmiSession, VmiVa as _,
    arch::amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt},
    driver::VmiFullDriver,
    os::{
        ProcessId, ProcessObject, ThreadId, ThreadObject, VmiOsProcess as _, VmiOsThread as _,
        windows::{WindowsFileObject, WindowsOs, WindowsOsExt as _},
    },
    trace::Hex,
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        bridge::Bridge,
        ptm::PageTableMonitor,
    },
};

use self::tracker::ProcessTracker;
use crate::{
    bridge::BridgeStatusCode,
    deploy::{DeployBridge, DeployPolicy, DeployStatus},
    file_transfer::{FileTransfer, FileTransferBridge},
};

/// Shortest observed `_EPROCESS.ImageFileName` truncation.
const MIN_TRUNCATED_PROCESS_NAME_LEN: usize = 14;

/// Matches a complete executable name or its kernel-truncated representation.
fn process_name_matches(expected: &str, observed: &str) -> bool {
    if expected.eq_ignore_ascii_case(observed) {
        return true;
    }

    observed.len() >= MIN_TRUNCATED_PROCESS_NAME_LEN
        && expected
            .get(..observed.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(observed))
}

fn process_matches_target<Driver>(
    expected_name: &str,
    expected_ppid: ProcessId,
    process: &Process<Driver>,
) -> bool
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    process_name_matches(expected_name, &process.name) && process.ppid == expected_ppid
}

/// Process metadata and process-local handles marked for transfer.
struct Process<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    pid: ProcessId,
    ppid: ProcessId,
    name: String,
    terminated: bool,
    file_transfers: HashMap<u64, FileTransfer<Driver>>,
}

impl<Driver> Process<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn mark_terminated(&mut self) {
        self.terminated = true;
    }

    fn mark_file(&mut self, transfer: FileTransfer<Driver>) {
        self.file_transfers.insert(transfer.handle(), transfer);
    }

    fn take_file(&mut self, handle: u64) -> Option<FileTransfer<Driver>> {
        self.file_transfers.remove(&handle)
    }
}

/// Thread metadata and the synchronous transfer currently using its stack.
struct Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    tid: ThreadId,
    terminated: bool,
    file_transfer: Option<FileTransfer<Driver>>,
}

impl<Driver> Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    fn mark_terminated(&mut self) {
        self.terminated = true;
    }
}

symbols! {
    #[derive(Debug)]
    struct Symbols {
        PspInsertProcess: u64,
        PspInsertThread: u64,
        KeTerminateThread: u64,
        MmCleanProcessAddressSpace: u64,
        NtWriteFile: u64,
        NtClose: u64,
    }
}

/// Terminal outcome produced by deploy monitoring.
pub type DeployMonitorOutput = Result<Option<ProcessId>, DeployStatus>;

/// Returns terminal process status or graceful external termination.
fn monitor_poll(
    completion: Option<DeployMonitorOutput>,
    terminated: bool,
) -> Option<DeployMonitorOutput> {
    completion.or_else(|| terminated.then_some(Ok(None)))
}

/// Monitors a deployed process from creation through address-space cleanup.
///
/// This is intentionally a proof-of-concept handler. Setup and event errors are
/// propagated or treated as fatal instead of maintaining a recovery state machine.
pub struct DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: View,
    bpm: BreakpointManager<BreakpointController<Driver>>,
    ptm: PageTableMonitor<Driver>,
    bridge: Bridge<WindowsOs<Driver>, (DeployBridge, FileTransferBridge), BridgeStatusCode>,
    processes: ProcessTracker<Process<Driver>, Thread<Driver>>,
    expected_name: String,
    expected_ppid: ProcessId,
    target_process: Option<ProcessObject>,
    completion: Option<DeployMonitorOutput>,
}

#[expect(non_snake_case)]
impl<Driver> DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Creates the monitor and installs all kernel breakpoints.
    pub fn new(
        session: &VmiSession<WindowsOs<Driver>>,
        profile: &Profile,
        terminate_flag: Arc<AtomicBool>,
        expected_name: String,
        expected_ppid: ProcessId,
        output_directory: PathBuf,
    ) -> Result<Self, VmiError> {
        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);
        let _pause_guard = vmi.pause_guard()?;
        let kernel_image_base = vmi.os().kernel_image_base()?;
        let root = vmi.os().system_process()?.translation_root()?;
        let symbols = Symbols::new(profile)?;

        vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;
        vmi.monitor_enable(EventMonitor::Hypercall {
            allow_userspace: true,
        })?;

        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();
        let mut install = |name: &'static str, offset: u64| -> Result<(), VmiError> {
            let va = kernel_image_base + offset;
            let context = (va, root);
            let breakpoint = Breakpoint::new(context, view).global().with_tag(name);
            bpm.insert(&vmi, breakpoint)?;
            ptm.monitor(&vmi, context, view, name)?;
            tracing::debug!(hook = name, %va, "installed deploy monitor hook");
            Ok(())
        };

        install("PspInsertProcess", symbols.PspInsertProcess)?;
        install("PspInsertThread", symbols.PspInsertThread)?;
        install("KeTerminateThread", symbols.KeTerminateThread)?;
        install(
            "MmCleanProcessAddressSpace",
            symbols.MmCleanProcessAddressSpace,
        )?;
        install("NtWriteFile", symbols.NtWriteFile)?;
        install("NtClose", symbols.NtClose)?;

        Ok(Self {
            terminate_flag,
            view,
            bpm,
            ptm,
            bridge: Bridge::new((
                DeployBridge::new(DeployPolicy::default().allow_execute()),
                FileTransferBridge::new(output_directory),
            )),
            processes: ProcessTracker::default(),
            expected_name,
            expected_ppid,
            target_process: None,
            completion: None,
        })
    }

    fn memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        if memory_access.access.contains(MemoryAccess::W) {
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());
            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("unhandled memory access: {memory_access:?}");
        }
    }

    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let tag = match self.bpm.get_by_event(vmi.event(), ()) {
            Some(breakpoint) => breakpoint.tag(),
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    tracing::warn!("unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }

                tracing::warn!("ignoring stale breakpoint event");
                return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
            }
        };

        match tag {
            "PspInsertProcess" => self.PspInsertProcess(vmi)?,
            "PspInsertThread" => self.PspInsertThread(vmi)?,
            "KeTerminateThread" => self.KeTerminateThread(vmi)?,
            "MmCleanProcessAddressSpace" => self.MmCleanProcessAddressSpace(vmi)?,
            "NtWriteFile" => self.NtWriteFile(vmi)?,
            "NtClose" => return self.NtClose(vmi),
            _ => panic!("unhandled deploy monitor hook: {tag}"),
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, events)?;
        Ok(VmiEventResponse::default().with_view(self.view))
    }

    /// Dispatches deploy and file-transfer hypercalls through the composed bridge.
    fn hypercall(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let hypercall = vmi.event().reason().as_hypercall();

        let mut registers = vmi.registers().gp_registers();
        registers.rip += hypercall.instruction_length as u64;

        if let Some(result) = self.bridge.dispatch(vmi) {
            match result {
                Ok(response) => response.write_to(&mut registers),
                Err(packet) => tracing::error!(
                    request = packet.request(),
                    method = packet.method(),
                    "empty bridge response"
                ),
            }
        }

        Ok(VmiEventResponse::default().with_registers(registers))
    }

    fn PspInsertProcess(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        //
        // NTSTATUS
        // PspInsertProcess (
        //     PEPROCESS NewProcess,
        //     PEPROCESS Parent,
        //     ULONG DesiredAccess,
        //     ULONG CreateFlags,
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
            file_transfers: HashMap::new(),
        };
        let is_target = self.target_process.is_none()
            && process_matches_target(&self.expected_name, self.expected_ppid, &process);

        tracing::info!(
            hook = "PspInsertProcess",
            process = %NewProcess,
            pid = %process.pid,
            name = %process.name,
            parent = %Parent,
            ppid = %process.ppid,
            "kernel function called"
        );

        self.processes.insert_process(NewProcess, process);

        if is_target {
            self.target_process = Some(NewProcess);
            let process = self
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

        Ok(())
    }

    fn PspInsertThread(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
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

        if self
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
            return Ok(());
        }

        tracing::info!(
            hook = "PspInsertThread",
            thread = %thread_object,
            %tid,
            process = %process_object,
            tracked = true,
            "kernel function called"
        );
        Ok(())
    }

    fn KeTerminateThread(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        //
        // VOID
        // KeTerminateThread (
        //     _In_ PKTHREAD Thread
        //     );
        //

        let thread_object = ThreadObject(Va(vmi.os().function_argument(0)?));
        let process_object = self.processes.process_of(thread_object);
        let thread = match self.processes.get_thread_mut(thread_object) {
            Some(thread) => thread,
            None => {
                tracing::info!(
                    hook = "KeTerminateThread",
                    thread = %thread_object,
                    tracked = false,
                    "kernel function called"
                );
                return Ok(());
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
        Ok(())
    }

    fn MmCleanProcessAddressSpace(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        //
        // VOID
        // MmCleanProcessAddressSpace (
        //     _In_ PEPROCESS Process
        //     );
        //

        let Process = ProcessObject(Va(vmi.os().function_argument(0)?));
        let thread_objects = self.processes.threads_of(Process).collect::<Vec<_>>();
        for thread_object in thread_objects {
            self.processes
                .get_thread_mut(thread_object)
                .expect("process thread index is consistent")
                .mark_terminated();
        }
        let process = match self.processes.get_process_mut(Process) {
            Some(process) => process,
            None => {
                tracing::info!(
                    hook = "MmCleanProcessAddressSpace",
                    process = %Process,
                    tracked = false,
                    "kernel function called"
                );
                return Ok(());
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

        if self.target_process == Some(Process) {
            self.completion = Some(Ok(Some(process.pid)));
            tracing::info!(
                process = %Process,
                pid = %process.pid,
                "deployed process terminated"
            );
        }

        Ok(())
    }

    fn NtWriteFile(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
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
        if self.target_process != Some(process_object) {
            return Ok(());
        }

        let FileHandle = vmi.os().function_argument(0)?;
        if vmi.os().is_kernel_handle(FileHandle)? {
            tracing::trace!(handle = %Hex(FileHandle), "ignoring kernel file handle");
            return Ok(());
        }

        let file_object = match current_process.lookup_object::<WindowsFileObject<_>>(FileHandle)? {
            Some(file_object) => file_object,
            None => {
                tracing::warn!(handle = %Hex(FileHandle), "cannot resolve file handle");
                return Ok(());
            }
        };
        let path = file_object.full_path()?;
        let process_id = self
            .processes
            .get_process(process_object)
            .expect("target process is tracked")
            .pid;
        let transfer = FileTransfer::new(FileHandle, file_object.va(), path.clone());
        self.processes
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
        Ok(())
    }

    fn NtClose(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // NTSTATUS
        // NTAPI
        // NtClose (
        //     _In_ _Post_ptr_invalid_ HANDLE Handle
        //     );
        //

        let thread_object = vmi.os().current_thread()?.object()?;
        if self
            .processes
            .get_thread(thread_object)
            .is_some_and(|thread| thread.file_transfer.is_some())
        {
            return self.advance_file_transfer(vmi, thread_object);
        }

        let current_process = vmi.os().current_process()?;
        let process_object = current_process.object()?;
        if self.target_process != Some(process_object) {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }
        if self.processes.get_thread(thread_object).is_none() {
            tracing::warn!(%thread_object, "close on untracked target thread");
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        let Handle = vmi.os().function_argument(0)?;
        if vmi.os().is_kernel_handle(Handle)? {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        let mut transfer = match self
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
        self.processes
            .get_thread_mut(thread_object)
            .expect("target thread checked above")
            .file_transfer = Some(transfer);
        self.advance_file_transfer(vmi, thread_object)
    }

    fn advance_file_transfer(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        thread_object: ThreadObject,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let thread = self
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

    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let result = match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            EventReason::Singlestep(_) => self.singlestep(vmi),
            EventReason::Hypercall(_) => self.hypercall(vmi),
            reason => panic!("unhandled deploy monitor event: {reason:?}"),
        };

        if let Err(VmiError::Translation(page_fault)) = result {
            tracing::warn!(?page_fault, "page fault, injecting");

            vmi.inject_interrupt(
                vmi.event().vcpu_id(),
                Interrupt::page_fault(page_fault.va, 0),
            )?;

            return Ok(VmiEventResponse::default());
        }

        result
    }
}

impl<Driver> VmiHandler<WindowsOs<Driver>> for DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    type Output = DeployMonitorOutput;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();
        self.dispatch(&vmi).expect("deploy monitor dispatch")
    }

    fn cleanup(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
            tracing::error!(%err, "failed to switch to the default view");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
            tracing::error!(%err, "failed to disable singlestep monitoring");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))
        {
            tracing::error!(%err, "failed to disable breakpoint monitoring");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Hypercall {
            allow_userspace: true,
        }) {
            tracing::error!(%err, "failed to disable hypercall monitoring");
        }

        match self.bpm.remove_by_view(vmi, self.view) {
            Ok(true) => {}
            Ok(false) => tracing::warn!("no deploy monitor breakpoints to remove"),
            Err(err) => tracing::error!(%err, "failed to remove deploy monitor breakpoints"),
        }
        self.ptm.unmonitor_all(vmi);

        if let Err(err) = vmi.destroy_view(self.view) {
            tracing::error!(%err, "failed to destroy deploy monitor view");
        }
    }

    fn poll(&self) -> Option<Self::Output> {
        monitor_poll(self.completion, self.terminate_flag.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use vmi::{driver::xen::VmiXenDriver, os::ProcessId};

    use super::*;

    fn process(name: &str, ppid: ProcessId) -> Process<VmiXenDriver<Amd64>> {
        Process {
            pid: ProcessId(100),
            ppid,
            name: name.to_owned(),
            terminated: false,
            file_transfers: HashMap::new(),
        }
    }

    #[test]
    fn target_process_requires_matching_name_and_parent() {
        assert!(!process_matches_target(
            "Sample.EXE",
            ProcessId(42),
            &process("other.exe", ProcessId(42)),
        ));
        assert!(!process_matches_target(
            "Sample.EXE",
            ProcessId(42),
            &process("sample.exe", ProcessId(7)),
        ));
        assert!(process_matches_target(
            "Sample.EXE",
            ProcessId(42),
            &process("sample.exe", ProcessId(42)),
        ));
    }

    #[test]
    fn target_process_accepts_kernel_truncated_name() {
        assert!(!process_matches_target(
            "dynasample-full.exe",
            ProcessId(42),
            &process("dynasample", ProcessId(42)),
        ));
        assert!(process_matches_target(
            "dynasample-full.exe",
            ProcessId(42),
            &process("dynasample-ful", ProcessId(42)),
        ));
    }

    #[test]
    fn termination_flag_completes_monitor_gracefully() {
        assert_eq!(monitor_poll(None, true), Some(Ok(None)));
        assert_eq!(monitor_poll(None, false), None);
    }
}
