mod hooks;

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
    os::{
        ProcessId, ProcessObject, ThreadId, ThreadObject, VmiOsProcess as _, VmiOsThread as _,
        windows::WindowsOs,
    },
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        bridge::Bridge,
        ptm::PageTableMonitor,
        tracker::Tracker,
    },
};

use self::hooks::MonitorHook;
use crate::{
    bridge::BridgeOutput,
    deploy::{DeployBridge, DeployPolicy, DeployStatus, ExecuteResponse},
    file_transfer::{FileTransfer, FileTransferBridge},
};

/// Process metadata and pending file transfers.
struct Process<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Process ID.
    pid: ProcessId,

    /// Parent process ID.
    ppid: ProcessId,

    /// Process name.
    name: String,

    /// Pending file transfers indexed by handles in this process.
    file_transfers: HashMap<u64, FileTransfer<Driver>>,
}

impl<Driver> Process<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Creates process metadata.
    fn new(pid: ProcessId, ppid: ProcessId, name: String) -> Self {
        Self {
            pid,
            ppid,
            name,
            file_transfers: HashMap::new(),
        }
    }

    /// Records a file transfer indexed by its handle.
    ///
    /// Returns `true` if the handle was not already present.
    fn record_file_transfer(&mut self, transfer: FileTransfer<Driver>) -> bool {
        self.file_transfers
            .insert(transfer.handle(), transfer)
            .is_none()
    }

    /// Removes and returns the file transfer for a handle.
    fn take_file_transfer(&mut self, handle: u64) -> Option<FileTransfer<Driver>> {
        self.file_transfers.remove(&handle)
    }
}

/// Thread metadata and the synchronous transfer currently using its stack.
struct Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Thread ID.
    #[expect(unused)]
    tid: ThreadId,

    /// Active file transfer using this thread's stack.
    file_transfer: Option<FileTransfer<Driver>>,
}

impl<Driver> Thread<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Creates thread metadata.
    fn new(tid: ThreadId) -> Self {
        Self {
            tid,
            file_transfer: None,
        }
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

/// State passed through kernel breakpoint dispatch.
struct MonitorState<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    /// Tracks process and thread metadata.
    tracker: Tracker<Process<Driver>, Thread<Driver>>,

    /// Thread performing the deployed process creation.
    creator_thread: Option<ThreadObject>,

    /// Process object of the deployed process, once discovered.
    target_process: Option<ProcessObject>,

    /// Result produced when the deployed process terminates.
    output: Option<<Monitor<Driver> as VmiHandler<WindowsOs<Driver>>>::Output>,
}

/// Monitor for a deployed process.
///
/// Setup and event errors are returned or treated as fatal. The monitor does
/// not attempt recovery.
pub struct Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: View,
    bpm: BreakpointManager<BreakpointController<Driver>, (), MonitorHook<Driver>>,
    ptm: PageTableMonitor<Driver, MonitorHook<Driver>>,
    bridge: Bridge<WindowsOs<Driver>, (DeployBridge, FileTransferBridge)>,
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
                    let hook = MonitorHook {
                        name: stringify!($name),
                        callback: self::hooks::$name::<Driver>,
                    };
                    let breakpoint = Breakpoint::new(context, view).global().with_tag(hook);
                    bpm.insert(&vmi, breakpoint)?;
                    ptm.monitor(&vmi, context, view, hook)?;
                    tracing::debug!(
                        ?hook,
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
                DeployBridge::new(
                    DeployPolicy::default().execute_response(ExecuteResponse::ContinueAndNotify),
                ),
                FileTransferBridge::new(output_directory),
            )),
            state: MonitorState {
                tracker: Tracker::default(),
                creator_thread: None,
                target_process: None,
                output: None,
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

        (hook.callback)(vmi, &mut self.state)
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

    /// Dispatches `deploy` and `file-transfer` hypercalls through the composed
    /// bridge.
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
                Ok(response) => {
                    response.write_to(&mut registers);

                    if let Some(output) = response.into_output() {
                        self.process_bridge(vmi, output)?;
                    }
                }
                Err(packet) => tracing::error!(
                    request = packet.request(),
                    method = packet.method(),
                    "empty bridge response"
                ),
            }
        }

        Ok(VmiEventResponse::default().with_registers(registers))
    }

    /// Processes host-side bridge outputs before the guest resumes.
    fn process_bridge(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        output: BridgeOutput,
    ) -> Result<(), VmiError> {
        match output {
            BridgeOutput::DeployExecuting => {
                if self.state.creator_thread.is_none() && self.state.target_process.is_none() {
                    let current_thread = vmi.os().current_thread()?;
                    self.state.creator_thread = Some(current_thread.object()?);
                }
                else {
                    tracing::warn!(
                        creator_thread = ?self.state.creator_thread,
                        target_process = ?self.state.target_process,
                        "ignoring repeated deploy execute notification"
                    );
                }
            }
            BridgeOutput::DeployWaiting | BridgeOutput::DeployFinished(_) => {}
        }

        Ok(())
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
    type Output = Result<Option<ProcessId>, DeployStatus>;

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

    fn poll(&mut self) -> Option<Self::Output> {
        self.state.output.or_else(|| {
            self.terminate_flag
                .load(Ordering::Relaxed)
                .then_some(Ok(None))
        })
    }
}
