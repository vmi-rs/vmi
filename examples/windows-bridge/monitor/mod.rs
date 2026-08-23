mod tracker;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
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

use self::tracker::{Process, ProcessTracker};
use crate::{
    bridge::TerminalStatus,
    deploy::{DeployBridge, DeployPolicy, DeployStatus},
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

fn process_matches_target(
    expected_name: &str,
    expected_ppid: ProcessId,
    process: &Process,
) -> bool {
    process_name_matches(expected_name, &process.name) && process.ppid == expected_ppid
}

/// Returns a terminal deploy status only when it represents failure.
fn deploy_failure(status: DeployStatus) -> Option<DeployStatus> {
    (status.status() != TerminalStatus::SUCCESS).then_some(status)
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
    processes: ProcessTracker,
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
            "MmCleanProcessAddressSpace" => self.MmCleanProcessAddressSpace(vmi)?,
            "NtWriteFile" => self.NtWriteFile(vmi)?,
            "NtClose" => self.NtClose(vmi)?,
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

    /// Releases the execute gate and observes the shellcode's terminal status.
    fn hypercall(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let hypercall = vmi.event().reason().as_hypercall();
        let mut registers = vmi.registers().gp_registers();
        registers.rip += hypercall.instruction_length as u64;

        let packet = BridgePacket::from(vmi);
        let mut bridge = DeployBridge::new(DeployPolicy::default().allow_execute());
        if let Some(result) = bridge.dispatch(vmi, packet) {
            let response = result
                .unwrap_or_else(|packet| panic!("unhandled deploy bridge packet: {packet:?}"));
            response.write_to(&mut registers);

            if let Some(packed) = response.into_result() {
                let status = DeployStatus::decode(packed);
                tracing::info!(?status, "deploy shellcode completed during monitoring");
                if let Some(status) = deploy_failure(status) {
                    self.completion = Some(Err(status));
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
        let new_process = vmi.os().process(NewProcess)?;
        let parent = vmi.os().process(Parent)?;
        let process = Process {
            pid: new_process.id()?,
            ppid: parent.id()?,
            name: new_process.name()?,
            terminated: false,
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

        self.processes.insert(NewProcess, process);

        if is_target {
            self.target_process = Some(NewProcess);
            let process = self.processes.get(NewProcess).expect("inserted process");
            tracing::info!(
                process = %NewProcess,
                pid = %process.pid,
                name = %process.name,
                "deployed process started"
            );
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
        let Some(process) = self.processes.mark_terminated(Process)
        else {
            tracing::info!(
                hook = "MmCleanProcessAddressSpace",
                process = %Process,
                tracked = false,
                "kernel function called"
            );
            return Ok(());
        };

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

    fn NtWriteFile(&self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
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

        let object = vmi.os().current_process()?.object()?;
        if let Some(process) = self.processes.get(object) {
            tracing::info!(
                hook = "NtWriteFile",
                process = %object,
                pid = %process.pid,
                ppid = %process.ppid,
                name = %process.name,
                terminated = process.terminated,
                tracked = true,
                "kernel function called"
            );
        }
        else {
            tracing::info!(
                hook = "NtWriteFile",
                process = %object,
                tracked = false,
                "kernel function called"
            );
        }

        Ok(())
    }

    fn NtClose(&self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        //
        // NTSTATUS
        // NTAPI
        // NtClose (
        //     _In_ _Post_ptr_invalid_ HANDLE Handle
        //     );
        //

        let object = vmi.os().current_process()?.object()?;
        if let Some(process) = self.processes.get(object) {
            tracing::info!(
                hook = "NtClose",
                process = %object,
                pid = %process.pid,
                ppid = %process.ppid,
                name = %process.name,
                terminated = process.terminated,
                tracked = true,
                "kernel function called"
            );
        }
        else {
            tracing::info!(
                hook = "NtClose",
                process = %object,
                tracked = false,
                "kernel function called"
            );
        }

        Ok(())
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
    use vmi::os::ProcessId;

    use super::*;
    use crate::{
        bridge::TerminalStatus,
        deploy::{DeployStage, DeployStatus},
    };

    fn process(name: &str, ppid: ProcessId) -> Process {
        Process {
            pid: ProcessId(100),
            ppid,
            name: name.to_owned(),
            terminated: false,
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
    fn terminal_deploy_failure_stops_monitoring() {
        let success = DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::SUCCESS);
        let failure = DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::OPERATION_FAILED);

        assert_eq!(deploy_failure(success), None);
        assert_eq!(deploy_failure(failure), Some(failure));
    }

    #[test]
    fn termination_flag_completes_monitor_gracefully() {
        assert_eq!(monitor_poll(None, true), Some(Ok(None)));
        assert_eq!(monitor_poll(None, false), None);
    }
}
