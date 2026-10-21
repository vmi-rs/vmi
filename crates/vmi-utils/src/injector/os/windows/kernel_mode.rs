use std::ops::ControlFlow;

use vmi_arch_amd64::{
    Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt, PageFaultErrorCode,
};
use vmi_core::{
    MemoryAccess, Registers as _, Va, VcpuId, View, VmiContext, VmiError, VmiEventResponse,
    VmiHandler, VmiSession,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead,
        VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    },
    os::{ProcessId, ThreadId, VmiOsProcess, VmiOsThread},
    trace::Hex,
};
use vmi_os_windows::{WindowsOs, WindowsOsExt as _, WindowsProcessorMode};

use super::super::super::{
    InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory, KernelMode, Recipe,
    RecipeExecutor,
};
use crate::{
    bpm::{Breakpoint, BreakpointController, BreakpointManager},
    bridge::{BridgeDispatch, BridgePacket},
    ptm::PageTableMonitor,
};

/// Lifecycle state of the kernel-mode injector.
enum InjectorState {
    /// Waiting for a thread to hit the hijack breakpoint.
    PreHijack,

    /// Thread hijacked; executing the injection recipe.
    Executing,

    /// Recipe finished or aborted; singlestepping to safely tear down
    /// monitoring.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// singlestep event from this specific vCPU signals that it has resumed
    /// past the breakpoint context, making it safe to tear down monitors
    /// and views. Singlestep events from other vCPUs are unrelated page
    /// table monitor activity and must not trigger teardown.
    Teardown(VcpuId),

    /// Monitoring torn down; waiting for bridge communication.
    Bridge,

    /// Injection complete; result is available.
    Complete,

    /// Injection failed before the hijack; error is available.
    Failed,
}

pub struct KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>>,
{
    /// Process ID being injected into.
    pid: Option<ProcessId>,

    /// Thread ID that was hijacked for injection.
    tid: Option<ThreadId>,

    /// Memory view used for injection operations.
    view: View,

    /// Breakpoint manager for setting and tracking hijack breakpoints.
    bpm: BreakpointManager<WindowsOs<Driver>, BreakpointController<Driver>>,

    /// Page table monitor for tracking page table modifications.
    ptm: PageTableMonitor<Driver>,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<WindowsOs<Driver>, T>,

    /// Bridge for guest-host communication.
    bridge: Bridge,

    /// Current lifecycle state of the injector.
    state: InjectorState,

    /// Output produced by the bridge.
    output: Option<Result<Bridge::Output, BridgePacket>>,

    /// Error that ended the injection.
    error: Option<VmiError>,
}

impl<Driver, T> InjectorHandlerFactory<WindowsOs<Driver>, KernelMode, T>
    for KernelInjectorHandler<Driver, T, ()>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    /// Creates a new injector handler.
    #[expect(non_snake_case)]
    fn new(
        vmi: &VmiSession<WindowsOs<Driver>>,
        recipe: Recipe<WindowsOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        vmi.monitor_enable(EventMonitor::interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::singlestep())?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();

        let paused = vmi.pause_guard()?;
        let vmi = paused.state();

        let kernel_image_base = vmi.os().kernel_image_base()?;
        let system_process = vmi.os().system_process()?;
        let root = system_process.translation_root()?;

        // Every syscall passes KiSystemServiceCopyEnd right before its service
        // routine is called. A thread making a syscall from user mode runs at
        // PASSIVE_LEVEL, has APCs enabled and holds no locks, so it can safely
        // call kernel functions. Syscalls from user mode are frequent, so the
        // breakpoint is hit almost immediately.
        let va_KiSystemServiceCopyEnd = kernel_image_base
            + vmi
                .os()
                .symbols()
                .KiSystemServiceCopyEnd
                .ok_or(VmiError::Other("KiSystemServiceCopyEnd not found"))?;
        let cx_KiSystemServiceCopyEnd = (va_KiSystemServiceCopyEnd, root);
        let bp_KiSystemServiceCopyEnd = Breakpoint::new(cx_KiSystemServiceCopyEnd, view)
            .global()
            .with_tag("KiSystemServiceCopyEnd");
        bpm.insert(&vmi, bp_KiSystemServiceCopyEnd)?;
        ptm.monitor(
            &vmi,
            cx_KiSystemServiceCopyEnd,
            view,
            "KiSystemServiceCopyEnd",
        )?;

        Ok(Self {
            pid: None,
            tid: None,
            view,
            bpm,
            ptm,
            recipe: RecipeExecutor::new(recipe),
            bridge: (),
            state: InjectorState::PreHijack,
            output: None,
            error: None,
        })
    }

    fn with_bridge<Bridge>(
        self,
        bridge: Bridge,
    ) -> Result<
        <WindowsOs<Driver> as InjectorExecutionAdapter<KernelMode, T, Bridge>>::Handler,
        VmiError,
    >
    where
        Bridge: BridgeDispatch<WindowsOs<Driver>>,
    {
        Ok(KernelInjectorHandler {
            pid: self.pid,
            tid: self.tid,
            view: self.view,
            bpm: self.bpm,
            ptm: self.ptm,
            recipe: self.recipe,
            bridge,
            state: InjectorState::PreHijack,
            output: None,
            error: None,
        })
    }
}

impl<Driver, T, Bridge> InjectorHandlerAdapter<WindowsOs<Driver>, KernelMode, T, Bridge>
    for KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>>,
{
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError> {
        Ok(Self {
            pid: Some(pid),
            ..self
        })
    }
}

impl<Driver, T, Bridge> KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>>,
{
    #[tracing::instrument(
        name = "injector",
        skip_all,
        fields(
            vcpu = %vmi.event().vcpu_id(),
            rip = %Va(vmi.registers().rip),
        )
    )]
    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::Interrupt(_) => self.on_interrupt(vmi),
            EventReason::Singlestep(_) => self.on_singlestep(vmi),
            EventReason::Hypercall(_) => self.on_hypercall(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        tracing::trace!(
            pa = %memory_access.pa,
            va = %memory_access.va,
            access = %memory_access.access,
        );

        if memory_access.access.contains(MemoryAccess::W) {
            // It is assumed that a write memory access event is caused by a
            // page table modification.
            //
            // The page table entry is marked as dirty in the page table monitor
            // and a singlestep is performed to process the dirty entries.
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());

            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            // When the guest tries to read from the memory, a fast-singlestep
            // is performed over the instruction that tried to read the memory.
            // This is done to allow the instruction to read the original memory
            // content.
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("Unhandled memory access: {memory_access:?}");
        }
    }

    #[tracing::instrument(name = "interrupt", skip_all)]
    fn on_interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match self.bpm.get_by_event(vmi, vmi.event(), ()) {
            Some(breakpoint) => {
                debug_assert_eq!(breakpoint.tag(), "KiSystemServiceCopyEnd");
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    // This breakpoint was not set by us. Reinject it.
                    tracing::warn!("unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                else {
                    // We have received a breakpoint event, but there is no
                    // breakpoint instruction at the current memory location.
                    // This can happen if the event was triggered by a breakpoint
                    // we just removed.
                    tracing::warn!("ignoring old breakpoint event");
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }
            }
        };

        //
        // Early exit if the recipe is no longer executing. An error can end
        // the injection before the breakpoint is removed.
        //

        if !matches!(
            self.state,
            InjectorState::PreHijack | InjectorState::Executing
        ) {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        let current_thread = vmi.os().current_thread()?;
        let current_tid = current_thread.id()?;

        match self.tid {
            Some(tid) => {
                //
                // Follow the hijacked thread by its ID. A recipe can attach
                // it to another process, which changes its current process.
                //

                if current_tid != tid {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }
            }
            None => {
                //
                // Skip syscalls from kernel mode.
                //
                // The kernel's own `Zw*` calls pass KiSystemServiceCopyEnd
                // too, with the previous mode set to `KernelMode`, and their
                // callers may hold locks.
                //

                if current_thread.previous_mode()? != WindowsProcessorMode::UserMode {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }

                let current_process = current_thread.current_process()?;

                //
                // Skip processes without a PEB.
                //
                // We want to avoid injecting into processes like "Registry" or
                // "MemCompression", because the functions called in the
                // shellcode would likely fail with access violations.
                //

                if current_process.peb()?.is_none() {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }

                let current_pid = current_process.id()?;

                if self.pid.is_none() {
                    tracing::trace!(%current_pid, "hijacking process");
                    self.pid = Some(current_pid);
                }
                else if Some(current_pid) != self.pid {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }

                self.tid = Some(current_tid);
                tracing::debug!(
                    session_id = current_process
                        .session()
                        .ok()
                        .flatten()
                        .and_then(|session| session.id().ok())
                        .unwrap_or(0),
                    %current_pid,
                    %current_tid,
                    filename = current_process
                        .name()
                        .as_deref()
                        .unwrap_or("<unknown>"),
                    "thread hijacked"
                );

                // A payload that the recipe starts in a user process reports
                // through the bridge from user mode.
                if !Bridge::EMPTY {
                    vmi.monitor_enable(EventMonitor::hypercall().allow_userspace(true))?;
                }

                self.state = InjectorState::Executing;
            }
        }

        //
        // Execute the next step in the recipe. After an error, abort the
        // recipe instead. The hijacked thread then resumes with its original
        // registers.
        //

        let new_registers = match &self.error {
            Some(_) => self.recipe.abort(vmi),
            None => match self.recipe.execute(vmi) {
                Ok(registers) => registers,
                Err(VmiError::PageFault(pf)) => return Err(VmiError::PageFault(pf)),
                Err(err) => {
                    tracing::error!(%err, "recipe failed");
                    self.error = Some(err);
                    self.recipe.abort(vmi)
                }
            },
        };

        let new_registers = match new_registers {
            Some(registers) => registers,
            None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
        };

        if self.error.is_none() && !self.recipe.done() {
            return Ok(VmiEventResponse::default().with_registers(new_registers.gp_registers()));
        }

        //
        // Terminal path: stop new breakpoint traps, then request exactly one
        // singlestep in the default view with restored registers.
        //
        // Cleanup is intentionally deferred to `on_singlestep`. If the tool
        // exits immediately after this event, monitor teardown may call
        // `xc_monitor_disable` before Xen's vCPU resume path (`hvm_do_resume`)
        // applies staged register changes. The follow-up singlestep event is
        // our rendezvous that the vCPU resumed once past this breakpoint
        // context, reducing that teardown-ordering race.
        //

        self.state = InjectorState::Teardown(vmi.event().vcpu_id());

        Ok(VmiEventResponse::singlestep()
            .with_registers(new_registers.gp_registers())
            .with_view(vmi.default_view()))
    }

    #[tracing::instrument(name = "singlestep", skip_all)]
    fn on_singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        if let InjectorState::Teardown(vcpu) = self.state
            && vcpu == vmi.event().vcpu_id()
        {
            debug_assert_eq!(vmi.event().view(), Some(vmi.default_view()));

            // Singlestep monitoring is NOT disabled here - `cleanup` handles it.
            //
            // On Xen, `monitor_disable(Singlestep)` calls `debug_control(OFF)`
            // on every vCPU, clearing per-vCPU `single_step` state. Calling it
            // during event handling creates a race with the response's singlestep
            // toggle, potentially trapping a vCPU in an infinite MTF loop.
            //
            // Instead, per-vCPU singlestep is disabled via the event response
            // (returning without the SINGLESTEP flag), and the global monitor
            // is disabled later in `cleanup`.
            vmi.switch_to_view(vmi.default_view())?;
            vmi.monitor_disable(EventMonitor::interrupt(ExceptionVector::Breakpoint))?;

            self.bpm.remove_by_view(vmi, self.view)?;
            self.ptm.unmonitor_view(vmi, self.view);

            vmi.destroy_view(self.view)?;

            if Bridge::EMPTY || self.output.is_some() || self.error.is_some() {
                self.state = InjectorState::Complete;
            }
            else {
                self.state = InjectorState::Bridge;
            }

            return Ok(VmiEventResponse::default());
        }

        // Get the page table modifications by processing the dirty page table
        // entries.
        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, ptm_events)?;

        // Disable singlestep and switch back to our view.
        Ok(VmiEventResponse::default().with_view(self.view))
    }

    #[tracing::instrument(name = "hypercall", skip_all)]
    fn on_hypercall(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let hypercall = vmi.event().reason().as_hypercall();

        let mut registers = vmi.registers().gp_registers();
        registers.rip += hypercall.instruction_length as u64;

        tracing::trace!(
            magic = %Hex(registers.rbp as u32),
            request = %Hex((registers.rcx & 0xFFFF) as u16),
            method = %Hex((registers.rcx >> 16) as u16),
        );

        if let Some(result) = self.bridge.dispatch(vmi, BridgePacket::from(vmi)) {
            let complete = match result {
                Ok(response) => {
                    response.write_to(&mut registers);
                    response.into_output().map(Ok)
                }
                Err(packet) => {
                    tracing::error!(
                        request = packet.request(),
                        method = packet.method(),
                        "empty bridge response"
                    );
                    Some(Err(packet))
                }
            };

            if let Some(complete) = complete {
                self.output = Some(complete);

                // If the recipe has already been torn down, we're done.
                if matches!(self.state, InjectorState::Bridge) {
                    self.state = InjectorState::Complete;
                }
            }
        }

        Ok(VmiEventResponse::default().with_registers(registers))
    }

    /// Records `err` as the error that ends the injection.
    ///
    /// Before the hijack, and while waiting for the bridge, the injection
    /// ends at once. While the recipe is executing or tearing down, it ends
    /// once the hijacked thread has its original registers back.
    fn on_error(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        err: VmiError,
    ) -> VmiEventResponse<Amd64> {
        tracing::error!(%err, "injection failed");

        if self.error.is_none() {
            self.error = Some(err);
        }

        match self.state {
            InjectorState::PreHijack => self.state = InjectorState::Failed,
            InjectorState::Bridge => self.state = InjectorState::Complete,
            InjectorState::Executing
            | InjectorState::Teardown(_)
            | InjectorState::Complete
            | InjectorState::Failed => {}
        }

        // A page table monitor singlestep runs in the default view. Switching
        // back keeps the hijack breakpoint in place for the hijacked thread,
        // which must still get its original registers back.
        match vmi.event().reason() {
            EventReason::Singlestep(_) if matches!(self.state, InjectorState::Executing) => {
                VmiEventResponse::default().with_view(self.view)
            }
            _ => VmiEventResponse::default(),
        }
    }
}

impl<Driver, T, Bridge> VmiHandler<WindowsOs<Driver>> for KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>>,
{
    type Output = Result<Option<Result<Bridge::Output, BridgePacket>>, VmiError>;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,
            Err(VmiError::PageFault(pf)) => {
                tracing::debug!(va = %pf.va, "injecting page fault");
                let _ = vmi.inject_interrupt(
                    vmi.event().vcpu_id(),
                    Interrupt::page_fault_with_error_code(pf.va, PageFaultErrorCode::empty()),
                );

                VmiEventResponse::default()
            }
            Err(err) => self.on_error(&vmi, err),
        }
    }

    fn handle_interrupted(&mut self, _vmi: &VmiSession<WindowsOs<Driver>>) -> ControlFlow<()> {
        let flow = match self.state {
            InjectorState::Complete | InjectorState::Failed => return ControlFlow::Break(()),

            // Nothing in the guest has changed yet.
            InjectorState::PreHijack => {
                self.state = InjectorState::Failed;
                ControlFlow::Break(())
            }

            // The hijacked thread already runs with its original registers.
            InjectorState::Bridge => {
                self.state = InjectorState::Complete;
                ControlFlow::Break(())
            }

            // The next return of the hijacked thread aborts the recipe.
            InjectorState::Executing | InjectorState::Teardown(_) => ControlFlow::Continue(()),
        };

        if self.error.is_none() {
            self.error = Some(VmiError::Other("injection interrupted"));
        }

        flow
    }

    fn cleanup(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        // Disabled when transitioning from `Teardown` to `Bridge` or `Complete`.
        let mut disable_interrupt = false;
        // Disabled when transitioning from `Teardown` or `Bridge` to `Complete`.
        let mut disable_hypercall = false;

        match self.state {
            InjectorState::PreHijack | InjectorState::Failed => {
                disable_interrupt = true;
            }
            InjectorState::Executing | InjectorState::Teardown(_) => {
                disable_interrupt = true;
                disable_hypercall = !Bridge::EMPTY;
            }
            InjectorState::Bridge | InjectorState::Complete => {
                disable_hypercall = !Bridge::EMPTY;
            }
        }

        // In `PreHijack`, `Executing`, or `Teardown` states, we are guaranteed to
        // have enabled the breakpoint monitor, so we must disable it.
        if disable_interrupt {
            if let Err(err) =
                vmi.monitor_disable(EventMonitor::interrupt(ExceptionVector::Breakpoint))
            {
                tracing::error!(%err, "failed to disable breakpoint monitor");
            }

            if let Err(err) = self.bpm.remove_by_view(vmi, self.view) {
                tracing::error!(%err, "failed to remove breakpoints");
            }

            self.ptm.unmonitor_view(vmi, self.view);

            if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
                tracing::error!(%err, "failed to switch to default view");
            }

            if let Err(err) = vmi.destroy_view(self.view) {
                tracing::error!(%err, "failed to destroy view");
            }
        }

        // After leaving `PreHijack` with a nonempty bridge, we are guaranteed to
        // have enabled the hypercall monitor, so we must disable it.
        if disable_hypercall && let Err(err) = vmi.monitor_disable(EventMonitor::hypercall()) {
            tracing::error!(%err, "failed to disable hypercall monitor");
        }

        // In all states, we are guaranteed to have enabled the singlestep
        // monitor, so we must disable it.
        if let Err(err) = vmi.monitor_disable(EventMonitor::singlestep()) {
            tracing::error!(%err, "failed to disable singlestep monitor");
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        match self.state {
            InjectorState::Complete | InjectorState::Failed => match self.error.take() {
                Some(err) => Some(Err(err)),
                None => Some(Ok(self.output.take())),
            },
            _ => None,
        }
    }
}
