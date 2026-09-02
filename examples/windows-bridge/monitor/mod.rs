//! Deploy monitor that installs kernel breakpoints and drains marked file transfers.

mod hooks;
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
    MemoryAccess, Registers as _, View, VmiContext, VmiError, VmiEventResponse, VmiHandler,
    VmiSession,
    arch::amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt},
    driver::VmiFullDriver,
    os::{ProcessId, ProcessObject, ThreadId, VmiOsProcess as _, windows::WindowsOs},
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

/// Matches a tracked process against the expected name and parent process id.
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
    /// Marks the process as terminated.
    fn mark_terminated(&mut self) {
        self.terminated = true;
    }

    /// Records a file transfer keyed by its handle.
    ///
    /// Returns `true` if the handle was not already present.
    fn mark_file(&mut self, transfer: FileTransfer<Driver>) -> bool {
        self.file_transfers
            .insert(transfer.handle(), transfer)
            .is_none()
    }

    /// Removes and returns the file transfer for a handle.
    fn take_file(&mut self, handle: u64) -> Option<FileTransfer<Driver>> {
        self.file_transfers.remove(&handle)
    }
}

/// Thread metadata and the synchronous transfer currently using its stack.
struct Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    #[expect(unused)]
    tid: ThreadId,
    terminated: bool,
    file_transfer: Option<FileTransfer<Driver>>,
}

impl<Driver> Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Marks the thread as terminated.
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
pub type MonitorOutput = Result<Option<ProcessId>, DeployStatus>;

/// Kernel breakpoint handler installed at a hooked function's entry.
type Hook<Driver> = fn(
    &VmiContext<WindowsOs<Driver>>,
    &mut MonitorState<Driver>,
) -> Result<VmiEventResponse<Amd64>, VmiError>;

/// Mutable monitor state threaded through kernel hook dispatch.
struct MonitorState<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    processes: ProcessTracker<Process<Driver>, Thread<Driver>>,
    expected_name: String,
    expected_ppid: ProcessId,
    target_process: Option<ProcessObject>,
    completion: Option<MonitorOutput>,
}

/// Returns terminal process status or graceful external termination.
fn monitor_poll(completion: Option<MonitorOutput>, terminated: bool) -> Option<MonitorOutput> {
    completion.or_else(|| terminated.then_some(Ok(None)))
}

/// Monitors a deployed process from creation through address-space cleanup.
///
/// This is intentionally a proof-of-concept handler. Setup and event errors are
/// propagated or treated as fatal instead of maintaining a recovery state machine.
pub struct Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: View,
    bpm: BreakpointManager<BreakpointController<Driver>, (), Hook<Driver>>,
    ptm: PageTableMonitor<Driver, Hook<Driver>>,
    bridge: Bridge<WindowsOs<Driver>, (DeployBridge, FileTransferBridge), BridgeStatusCode>,
    state: MonitorState<Driver>,
}

impl<Driver> Monitor<Driver>
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
        let paused = session.pause_guard()?;
        let vmi = paused.state();

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

        macro_rules! install {
            ($($name:ident),+ $(,)?) => {
                $(
                    let va = kernel_image_base + symbols.$name;
                    let context = (va, root);
                    let hook = hooks::$name::<Driver> as Hook<Driver>;
                    let breakpoint = Breakpoint::new(context, view).global().with_tag(hook);
                    bpm.insert(&vmi, breakpoint)?;
                    ptm.monitor(&vmi, context, view, hook)?;
                    tracing::debug!(
                        hook = stringify!($name),
                        %va,
                        "installed monitor hook"
                    );
                )+
            };
        }

        install!(
            PspInsertProcess,
            PspInsertThread,
            KeTerminateThread,
            MmCleanProcessAddressSpace,
            NtWriteFile,
            NtClose,
        );

        Ok(Self {
            terminate_flag,
            view,
            bpm,
            ptm,
            bridge: Bridge::new((
                DeployBridge::new(DeployPolicy::default().allow_execute()),
                FileTransferBridge::new(output_directory),
            )),
            state: MonitorState {
                processes: ProcessTracker::default(),
                expected_name,
                expected_ppid,
                target_process: None,
                completion: None,
            },
        })
    }

    #[tracing::instrument(skip_all)]
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

    #[tracing::instrument(skip_all)]
    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let hook = match self.bpm.get_by_event(vmi.event(), ()) {
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

        hook(vmi, &mut self.state)
    }

    #[tracing::instrument(skip_all)]
    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, events)?;
        Ok(VmiEventResponse::default().with_view(self.view))
    }

    /// Dispatches deploy and file-transfer hypercalls through the composed bridge.
    #[tracing::instrument(skip_all)]
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

    #[tracing::instrument(
        name = "monitor",
        skip_all,
        fields(
            pid = vmi::trace::current_process_id(vmi),
            tid = vmi::trace::current_thread_id(vmi),
        )
    )]
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

impl<Driver> VmiHandler<WindowsOs<Driver>> for Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    type Output = MonitorOutput;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,
            Err(err) => panic!("deploy monitor dispatch failed: {err:?}"),
        }
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
        monitor_poll(
            self.state.completion,
            self.terminate_flag.load(Ordering::Relaxed),
        )
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
