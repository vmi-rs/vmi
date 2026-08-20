use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use isr::{Profile, macros::symbols};
use vmi::{
    MemoryAccess, Registers as _, Va, VcpuId, View, VmiContext, VmiError, VmiEventResponse,
    VmiHandler, VmiSession,
    arch::amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt},
    driver::VmiFullDriver,
    os::{ProcessId, ProcessObject, VmiOsProcess as _, windows::WindowsOs},
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        bridge::{BridgeDispatch, BridgePacket},
        ptm::PageTableMonitor,
    },
};

use crate::{
    bridge::{BRIDGE_MAGIC, TerminalStatus},
    deploy::{DeployBridge, DeployPolicy, DeployStatus},
};

/// Response selected when the parked shellcode retries its execute gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecuteGateDecision {
    Continue,
    Abort,
}

/// Shutdown behavior selected when the VMI wait is interrupted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptionAction {
    AbortGate,
    Cancel,
}

/// View selection used while draining events after monitor cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorViewState {
    Active(View),
    Cleared(View),
}

/// Selects the monitoring view or the safe post-cleanup default.
fn monitor_view_state(view: Option<View>, default_view: View) -> MonitorViewState {
    match view {
        Some(view) => MonitorViewState::Active(view),
        None => MonitorViewState::Cleared(default_view),
    }
}

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

/// Process identity tracked across process insertion and address-space cleanup.
#[derive(Debug)]
struct MonitorState {
    expected_name: String,
    expected_parent: ProcessId,
    gate_released: bool,
    deferred_failure: Option<String>,
    tracked_process: Option<(ProcessObject, ProcessId)>,
}

impl MonitorState {
    /// Creates process tracking state for one deploy execution.
    fn new(expected_name: impl Into<String>, expected_parent: ProcessId) -> Self {
        Self {
            expected_name: expected_name.into(),
            expected_parent,
            gate_released: false,
            deferred_failure: None,
            tracked_process: None,
        }
    }

    /// Selects the first process matching the executable name and parent.
    fn observe_process(
        &mut self,
        process: ProcessObject,
        process_id: ProcessId,
        name: &str,
        parent_id: ProcessId,
    ) -> bool {
        if self.tracked_process.is_some()
            || !process_name_matches(&self.expected_name, name)
            || parent_id != self.expected_parent
        {
            return false;
        }

        self.tracked_process = Some((process, process_id));
        true
    }

    /// Chooses whether the parked shellcode may pass its execute gate.
    fn handle_execute_gate(&mut self, abort_requested: bool) -> ExecuteGateDecision {
        if abort_requested {
            return ExecuteGateDecision::Abort;
        }

        self.gate_released = true;
        ExecuteGateDecision::Continue
    }

    /// Reports whether execution has been released.
    fn gate_released(&self) -> bool {
        self.gate_released
    }

    /// Chooses signal handling without abandoning a parked execute gate.
    fn interruption_action(&self) -> InterruptionAction {
        if self.gate_released {
            InterruptionAction::Cancel
        }
        else {
            InterruptionAction::AbortGate
        }
    }

    /// Returns a terminal deploy status only when it represents failure.
    fn deploy_failure(&self, status: DeployStatus) -> Option<DeployStatus> {
        (status.status() != TerminalStatus::SUCCESS).then_some(status)
    }

    /// Defers failures while the shellcode still owns a parked execute gate.
    fn record_failure(&mut self, error: String) -> Option<String> {
        if self.gate_released {
            Some(error)
        }
        else {
            self.deferred_failure = Some(error);
            None
        }
    }

    /// Returns the failure that must be reported after aborting the gate.
    fn deferred_failure(&self) -> Option<&str> {
        self.deferred_failure.as_deref()
    }

    /// Reports whether cleanup belongs to the selected process object.
    fn observe_process_cleanup(&self, process: ProcessObject) -> bool {
        matches!(
            self.tracked_process,
            Some((tracked_process, _)) if tracked_process == process
        )
    }

    /// Returns the selected process object and PID.
    fn tracked_process(&self) -> Option<(ProcessObject, ProcessId)> {
        self.tracked_process
    }
}

symbols! {
    #[derive(Debug)]
    struct Symbols {
        PspInsertProcess: u64,
        MmCleanProcessAddressSpace: u64,
        NtWriteFile: u64,
        NtClose: u64,
    }
}

/// Terminal outcome produced by deploy monitoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployMonitorOutput {
    /// The selected process reached address-space cleanup.
    ProcessTerminated {
        /// PID assigned to the selected process.
        process_id: ProcessId,
    },

    /// The deploy shellcode reported a terminal failure.
    DeployFailed(DeployStatus),

    /// Monitoring was cancelled through the shared termination flag.
    Cancelled,

    /// Monitor setup or bridge dispatch failed.
    Failed(String),
}

/// Captures handler output when `VmiSession` stops on an interrupted wait.
#[derive(Debug, Clone, Default)]
pub struct DeployMonitorInterruptedOutput {
    output: Arc<Mutex<Option<DeployMonitorOutput>>>,
}

impl DeployMonitorInterruptedOutput {
    /// Removes and returns the captured interrupted handler output.
    pub fn take(&self) -> Option<DeployMonitorOutput> {
        self.output
            .lock()
            .expect("deploy monitor interrupted output poisoned")
            .take()
    }

    /// Captures the output produced while handling an interrupted wait.
    fn record(&self, output: DeployMonitorOutput) {
        *self
            .output
            .lock()
            .expect("deploy monitor interrupted output poisoned") = Some(output);
    }
}

/// Monitors a deployed process from creation through address-space cleanup.
pub struct DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: Option<View>,
    bpm: BreakpointManager<BreakpointController<Driver>>,
    ptm: PageTableMonitor<Driver>,
    state: MonitorState,
    completion: Option<DeployMonitorOutput>,
    interrupted_output: DeployMonitorInterruptedOutput,
    hypercall_enabled: bool,
    interrupt_enabled: bool,
    singlestep_enabled: bool,
}

#[expect(non_snake_case)]
impl<Driver> DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Creates a monitor and installs all kernel breakpoints before gate release.
    pub fn new(
        session: &VmiSession<WindowsOs<Driver>>,
        profile: &Profile,
        terminate_flag: Arc<AtomicBool>,
        interrupted_output: DeployMonitorInterruptedOutput,
        expected_name: String,
        expected_parent: ProcessId,
    ) -> Result<Self, VmiError> {
        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);
        let _pause_guard = vmi.pause_guard()?;

        let mut monitor = Self {
            terminate_flag,
            view: None,
            bpm: BreakpointManager::new(),
            ptm: PageTableMonitor::new(),
            state: MonitorState::new(expected_name, expected_parent),
            completion: None,
            interrupted_output,
            hypercall_enabled: false,
            interrupt_enabled: false,
            singlestep_enabled: false,
        };

        vmi.monitor_enable(EventMonitor::Hypercall {
            allow_userspace: true,
        })?;
        monitor.hypercall_enabled = true;

        let setup_result: Result<(), VmiError> = (|| {
            let kernel_image_base = vmi.os().kernel_image_base()?;
            let root = vmi.os().system_process()?.translation_root()?;
            let symbols = Symbols::new(profile)?;

            vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
            monitor.interrupt_enabled = true;
            vmi.monitor_enable(EventMonitor::Singlestep)?;
            monitor.singlestep_enabled = true;

            let view = vmi.create_view(MemoryAccess::RWX)?;
            monitor.view = Some(view);
            vmi.switch_to_view(view)?;

            let mut install = |name: &'static str, offset: u64| -> Result<(), VmiError> {
                let va = kernel_image_base + offset;
                let context = (va, root);
                let breakpoint = Breakpoint::new(context, view).global().with_tag(name);
                monitor.bpm.insert(&vmi, breakpoint)?;
                monitor.ptm.monitor(&vmi, context, view, name)?;
                tracing::debug!(hook = name, %va, "installed deploy monitor hook");
                Ok(())
            };

            install("PspInsertProcess", symbols.PspInsertProcess)?;
            install(
                "MmCleanProcessAddressSpace",
                symbols.MmCleanProcessAddressSpace,
            )?;
            install("NtWriteFile", symbols.NtWriteFile)?;
            install("NtClose", symbols.NtClose)?;

            Ok(())
        })();

        if let Err(err) = setup_result {
            monitor.clear_hook_state(vmi.session());
            let _ = monitor.state.record_failure(err.to_string());
        }

        Ok(monitor)
    }

    /// Removes breakpoint and view state while optionally retaining hypercalls.
    fn clear_hook_state(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
            tracing::error!(%err, "failed to switch to the default view");
        }

        if self.singlestep_enabled {
            if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
                tracing::error!(%err, "failed to disable singlestep monitoring");
            }
            self.singlestep_enabled = false;
        }

        if self.interrupt_enabled {
            if let Err(err) =
                vmi.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))
            {
                tracing::error!(%err, "failed to disable breakpoint monitoring");
            }
            self.interrupt_enabled = false;
        }

        if let Some(view) = self.view.take() {
            match self.bpm.remove_by_view(vmi, view) {
                Ok(true) => {}
                Ok(false) => tracing::warn!("no deploy monitor breakpoints to remove"),
                Err(err) => tracing::error!(%err, "failed to remove deploy monitor breakpoints"),
            }
            self.ptm.unmonitor_view(vmi, view);

            if let Err(err) = vmi.destroy_view(view) {
                tracing::error!(%err, "failed to destroy deploy monitor view");
            }
        }
    }

    /// Handles page permissions used by the breakpoint and page-table managers.
    fn memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();
        let view = match monitor_view_state(self.view, vmi.default_view()) {
            MonitorViewState::Active(view) => view,
            MonitorViewState::Cleared(default_view) => {
                return Ok(VmiEventResponse::fast_singlestep(default_view));
            }
        };

        if memory_access.access.contains(MemoryAccess::W) {
            self.ptm
                .mark_dirty_entry(memory_access.pa, view, vmi.event().vcpu_id());
            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("unhandled memory access: {memory_access:?}");
        }
    }

    /// Dispatches one managed breakpoint.
    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        if let MonitorViewState::Cleared(default_view) =
            monitor_view_state(self.view, vmi.default_view())
        {
            return Ok(VmiEventResponse::fast_singlestep(default_view));
        }

        let tag = match self.bpm.get_by_event(vmi.event(), ()) {
            Some(breakpoints) => breakpoints
                .into_iter()
                .next()
                .expect("managed breakpoint")
                .tag(),
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
            "MmCleanProcessAddressSpace" => self.MmCleanProcessAddressSpace(vmi)?,
            "NtWriteFile" => self.NtWriteFile(vmi),
            "NtClose" => self.NtClose(vmi),
            _ => panic!("unhandled deploy monitor hook: {tag}"),
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    /// Processes page-table changes and restores the monitoring view.
    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let view = match monitor_view_state(self.view, vmi.default_view()) {
            MonitorViewState::Active(view) => view,
            MonitorViewState::Cleared(default_view) => {
                return Ok(VmiEventResponse::default().with_view(default_view));
            }
        };

        let events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, events)?;

        Ok(VmiEventResponse::default().with_view(view))
    }

    /// Resumes or aborts the parked execute gate and observes terminal status.
    fn hypercall(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let hypercall = vmi.event().reason().as_hypercall();
        let mut registers = vmi.registers().gp_registers();
        registers.rip += hypercall.instruction_length as u64;

        let packet = BridgePacket::from(vmi);
        let is_execute = packet.magic() == BRIDGE_MAGIC
            && packet.request() == DeployBridge::REQUEST
            && packet.method() == DeployBridge::METHOD_EXECUTE;
        let abort_requested = self.state.deferred_failure().is_some()
            || (!self.state.gate_released() && self.terminate_flag.load(Ordering::Relaxed));
        let decision = is_execute.then(|| self.state.handle_execute_gate(abort_requested));
        let policy = match decision {
            Some(ExecuteGateDecision::Abort) => DeployPolicy::default(),
            _ => DeployPolicy::default().allow_execute(),
        };
        let mut bridge = DeployBridge::new(policy);

        if let Some(result) = bridge.dispatch(vmi, packet) {
            match result {
                Ok(response) => {
                    response.write_to(&mut registers);
                    let terminal_result = response.into_result();

                    if decision == Some(ExecuteGateDecision::Abort) {
                        self.completion = Some(match self.state.deferred_failure() {
                            Some(err) => DeployMonitorOutput::Failed(err.to_owned()),
                            None => DeployMonitorOutput::Cancelled,
                        });
                    }

                    if let Some(packed) = terminal_result {
                        let status = DeployStatus::decode(packed);
                        tracing::info!(?status, "deploy shellcode completed during monitoring");
                        if let Some(status) = self.state.deploy_failure(status) {
                            self.completion = Some(DeployMonitorOutput::DeployFailed(status));
                        }
                    }
                }
                Err(packet) => {
                    let error = format!("unhandled deploy bridge packet: {packet:?}");
                    if let Some(error) = self.state.record_failure(error) {
                        self.completion = Some(DeployMonitorOutput::Failed(error));
                    }
                }
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
        let process = vmi.os().process(NewProcess)?;
        let parent = vmi.os().process(Parent)?;
        let process_id = process.id()?;
        let parent_id = parent.id()?;
        let name = process.name()?;

        tracing::info!(
            hook = "PspInsertProcess",
            process = %NewProcess,
            %process_id,
            name,
            parent = %Parent,
            %parent_id,
            "kernel function called"
        );

        if self
            .state
            .observe_process(NewProcess, process_id, &name, parent_id)
        {
            tracing::info!(%NewProcess, %process_id, name, "deployed process started");
        }

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
        let process = vmi.os().process(Process)?;
        let process_id = process.id()?;
        let name = process.name()?;

        tracing::info!(
            hook = "MmCleanProcessAddressSpace",
            process = %Process,
            %process_id,
            name,
            "kernel function called"
        );

        if self.state.observe_process_cleanup(Process) {
            let (_, tracked_process_id) = self.state.tracked_process().expect("selected process");
            self.completion = Some(DeployMonitorOutput::ProcessTerminated {
                process_id: tracked_process_id,
            });
            tracing::info!(%Process, %tracked_process_id, "deployed process terminated");
        }

        Ok(())
    }

    fn NtWriteFile(&mut self, _vmi: &VmiContext<WindowsOs<Driver>>) {
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

        tracing::info!(hook = "NtWriteFile", "kernel function called");
    }

    fn NtClose(&mut self, _vmi: &VmiContext<WindowsOs<Driver>>) {
        //
        // NTSTATUS
        // NTAPI
        // NtClose (
        //     _In_ _Post_ptr_invalid_ HANDLE Handle
        //     );
        //

        tracing::info!(hook = "NtClose", "kernel function called");
    }

    /// Routes one VMI event to the monitor subsystem that owns it.
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

    /// Records an event error without bypassing gate abort or monitor cleanup.
    fn handle_dispatch_error(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        err: VmiError,
    ) -> VmiEventResponse<Amd64> {
        let error = format!("deploy monitor event failed: {err}");
        tracing::error!(%err, "deploy monitor event failed");

        if let Some(error) = self.state.record_failure(error) {
            self.completion = Some(DeployMonitorOutput::Failed(error));
        }

        match vmi.event().reason() {
            EventReason::MemoryAccess(_) | EventReason::Interrupt(_) => {
                VmiEventResponse::fast_singlestep(vmi.default_view())
            }
            EventReason::Singlestep(_) => VmiEventResponse::default().with_view(vmi.default_view()),
            EventReason::Hypercall(hypercall) => {
                let mut registers = vmi.registers().gp_registers();
                registers.rip += hypercall.instruction_length as u64;
                VmiEventResponse::default().with_registers(registers)
            }
            _ => VmiEventResponse::default(),
        }
    }
}

impl<Driver> VmiHandler<WindowsOs<Driver>> for DeployMonitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    type Output = DeployMonitorOutput;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();
        match self.dispatch(&vmi) {
            Ok(response) => response,
            Err(err) => self.handle_dispatch_error(&vmi, err),
        }
    }

    fn handle_interrupted(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        match self.state.interruption_action() {
            InterruptionAction::Cancel => {
                self.completion = Some(DeployMonitorOutput::Cancelled);
            }
            InterruptionAction::AbortGate => {
                while self.completion.is_none() && !self.state.gate_released() {
                    match vmi.wait_for_event(Duration::from_secs(1), self) {
                        Ok(()) | Err(VmiError::Timeout) => {}
                        Err(VmiError::Io(err)) if err.kind() == std::io::ErrorKind::Interrupted => {
                        }
                        Err(err) => {
                            tracing::error!(%err, "failed while aborting parked execute gate");
                            let _ = self.state.record_failure(format!(
                                "failed while aborting the parked execute gate: {err}"
                            ));
                        }
                    }
                }
            }
        }

        if let Some(completion) = &self.completion {
            self.interrupted_output.record(completion.clone());
        }
    }

    fn cleanup(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        self.clear_hook_state(vmi);

        if self.hypercall_enabled {
            if let Err(err) = vmi.monitor_disable(EventMonitor::Hypercall {
                allow_userspace: true,
            }) {
                tracing::error!(%err, "failed to disable hypercall monitoring");
            }
            self.hypercall_enabled = false;
        }
    }

    fn poll(&self) -> Option<Self::Output> {
        if let Some(completion) = &self.completion {
            return Some(completion.clone());
        }

        (self.state.gate_released() && self.terminate_flag.load(Ordering::Relaxed))
            .then_some(DeployMonitorOutput::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use vmi::{
        Va,
        os::{ProcessId, ProcessObject},
    };

    use super::*;
    use crate::{
        bridge::TerminalStatus,
        deploy::{DeployStage, DeployStatus},
    };

    #[test]
    fn process_selection_requires_matching_name_and_parent() {
        let mut state = MonitorState::new("Sample.EXE", ProcessId(42));

        assert!(!state.observe_process(
            ProcessObject(Va(0x1000)),
            ProcessId(100),
            "other.exe",
            ProcessId(42),
        ));
        assert!(!state.observe_process(
            ProcessObject(Va(0x2000)),
            ProcessId(200),
            "sample.exe",
            ProcessId(7),
        ));
        assert!(state.observe_process(
            ProcessObject(Va(0x3000)),
            ProcessId(300),
            "sample.exe",
            ProcessId(42),
        ));
        assert_eq!(
            state.tracked_process(),
            Some((ProcessObject(Va(0x3000)), ProcessId(300)))
        );
        assert!(!state.observe_process(
            ProcessObject(Va(0x4000)),
            ProcessId(400),
            "SAMPLE.EXE",
            ProcessId(42),
        ));
    }

    #[test]
    fn process_selection_accepts_kernel_truncated_name() {
        let mut state = MonitorState::new("dynasample-full.exe", ProcessId(42));

        assert!(!state.observe_process(
            ProcessObject(Va(0x1000)),
            ProcessId(100),
            "dynasample",
            ProcessId(42),
        ));
        assert!(state.observe_process(
            ProcessObject(Va(0x2000)),
            ProcessId(200),
            "dynasample-ful",
            ProcessId(42),
        ));
    }

    #[test]
    fn process_cleanup_requires_exact_selected_object() {
        let mut state = MonitorState::new("sample.exe", ProcessId(42));
        let selected = ProcessObject(Va(0x1000));

        assert!(!state.observe_process_cleanup(selected));
        assert!(state.observe_process(selected, ProcessId(100), "sample.exe", ProcessId(42),));
        assert!(!state.observe_process_cleanup(ProcessObject(Va(0x2000))));
        assert!(state.observe_process_cleanup(selected));
    }

    #[test]
    fn execute_gate_continues_normally_and_aborts_on_request() {
        let mut running = MonitorState::new("sample.exe", ProcessId(42));
        assert_eq!(
            running.handle_execute_gate(false),
            ExecuteGateDecision::Continue
        );
        assert!(running.gate_released());

        let mut cancelled = MonitorState::new("sample.exe", ProcessId(42));
        assert_eq!(
            cancelled.handle_execute_gate(true),
            ExecuteGateDecision::Abort
        );
        assert!(!cancelled.gate_released());
    }

    #[test]
    fn terminal_deploy_failure_stops_monitoring() {
        let state = MonitorState::new("sample.exe", ProcessId(42));
        let success = DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::SUCCESS);
        let failure = DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::OPERATION_FAILED);

        assert_eq!(state.deploy_failure(success), None);
        assert_eq!(state.deploy_failure(failure), Some(failure));
    }

    #[test]
    fn interruption_aborts_before_release_and_cancels_after_release() {
        let mut state = MonitorState::new("sample.exe", ProcessId(42));
        assert_eq!(state.interruption_action(), InterruptionAction::AbortGate);

        assert_eq!(
            state.handle_execute_gate(false),
            ExecuteGateDecision::Continue
        );
        assert_eq!(state.interruption_action(), InterruptionAction::Cancel);
    }

    #[test]
    fn failure_is_deferred_until_the_execute_gate_is_released() {
        let mut parked = MonitorState::new("sample.exe", ProcessId(42));
        assert_eq!(parked.record_failure("before".to_owned()), None);
        assert_eq!(parked.deferred_failure(), Some("before"));

        let mut running = MonitorState::new("sample.exe", ProcessId(42));
        assert_eq!(
            running.handle_execute_gate(false),
            ExecuteGateDecision::Continue
        );
        assert_eq!(
            running.record_failure("after".to_owned()),
            Some("after".to_owned())
        );
        assert_eq!(running.deferred_failure(), None);
    }

    #[test]
    fn pending_event_uses_default_view_after_monitor_cleanup() {
        assert_eq!(
            monitor_view_state(None, View(1)),
            MonitorViewState::Cleared(View(1))
        );
        assert_eq!(
            monitor_view_state(Some(View(2)), View(1)),
            MonitorViewState::Active(View(2))
        );
    }

    #[test]
    fn interrupted_output_preserves_handler_failure() {
        let interrupted_output = DeployMonitorInterruptedOutput::default();
        let failure = DeployMonitorOutput::Failed("event failure".to_owned());

        interrupted_output.record(failure.clone());

        assert_eq!(interrupted_output.take(), Some(failure));
        assert_eq!(interrupted_output.take(), None);
    }
}
