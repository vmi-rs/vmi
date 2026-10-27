use std::{
    ops::ControlFlow,
    time::{Duration, Instant},
};

use vmi_arch_amd64::{Amd64, EventMonitor, EventReason, Interrupt, Msr};
use vmi_core::{
    Architecture as _, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    driver::{
        VmiDriver, VmiEventControl, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl,
        VmiWrite,
    },
    os::{ProcessId, ThreadId, VmiOsImageArchitecture, VmiOsProcess, VmiOsThread},
    trace::Hex,
};
use vmi_os_windows::{WindowsOs, WindowsOsExt as _};

use super::{
    super::super::{
        InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory, Recipe,
        RecipeExecutor, UserMode,
    },
    DEFAULT_GRACE_TIMEOUT,
};
use crate::bridge::{BridgeDispatch, BridgePacket};

// const INVALID_VA: Va = Va(0xffff_ffff_ffff_ffff);
const INVALID_VIEW: View = View(0xffff);
// const INVALID_TID: ThreadId = ThreadId(0xffff_ffff);
// const INVALID_PID: ProcessId = ProcessId(0xffff_ffff);

/// Lifecycle state of the user-mode injector.
enum InjectorState {
    /// Waiting for target process MSR write; scanning trap frames for
    /// a viable user-mode instruction pointer to hijack.
    PreHijack,

    /// Thread hijacked; executing the injection recipe.
    Executing,

    /// Recipe finished or aborted; singlestepping to safely tear down
    /// monitoring.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// singlestep event from this specific vCPU signals that it has resumed
    /// past the memory access context, making it safe to tear down monitors
    /// and views.
    Teardown(VcpuId),

    /// Monitoring torn down; waiting for bridge communication.
    Bridge,

    /// Injection complete; result is available.
    Complete,

    /// Injection failed before the hijack; error is available.
    Failed,
}

pub struct UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64> + VmiRead,
    Bridge: BridgeDispatch<WindowsOs<Driver>>,
{
    /// Process ID being injected into.
    pid: Option<ProcessId>,

    /// Thread ID that was hijacked for injection.
    tid: Option<ThreadId>,

    /// Memory view used for injection operations.
    view: View,

    /// Virtual address of the instruction pointer in the hijacked thread.
    ip_va: Option<Va>,

    /// Physical address of the instruction pointer in the hijacked thread.
    ip_pa: Option<Pa>,

    /// The start of the grace period. The injector starts it when it skips
    /// its first thread.
    grace_since: Option<Instant>,

    /// Grace period in which the injector skips threads that their
    /// scheduling group holds back.
    grace_timeout: Duration,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<WindowsOs<Driver>, T>,

    /// Bridge.
    bridge: Bridge,

    /// Current lifecycle state of the injector.
    state: InjectorState,

    /// Output produced by the bridge.
    output: Option<Result<Bridge::Output, BridgePacket>>,

    /// Error that ended the injection.
    error: Option<VmiError>,
}

impl<Driver, T> InjectorHandlerFactory<WindowsOs<Driver>, UserMode, T>
    for UserInjectorHandler<Driver, T, ()>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    fn new(
        vmi: &VmiSession<WindowsOs<Driver>>,
        recipe: Recipe<WindowsOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        // A thread that runs again on the same CPU writes the same TEB to
        // `KERNEL_GS_BASE`. We need to monitor all writes, not just changes,
        // to detect that the thread has been scheduled.
        vmi.monitor_enable(EventMonitor::msr(Msr::KERNEL_GS_BASE).on_change_only(false))?;
        vmi.monitor_enable(EventMonitor::singlestep())?;

        Ok(Self {
            pid: None,
            tid: None,
            view,
            ip_va: None,
            ip_pa: None,
            grace_since: None,
            grace_timeout: DEFAULT_GRACE_TIMEOUT,
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
        <WindowsOs<Driver> as InjectorExecutionAdapter<UserMode, T, Bridge>>::Handler,
        VmiError,
    >
    where
        Bridge: BridgeDispatch<WindowsOs<Driver>>,
    {
        Ok(UserInjectorHandler {
            pid: self.pid,
            tid: self.tid,
            view: self.view,
            ip_va: self.ip_va,
            ip_pa: self.ip_pa,
            grace_since: self.grace_since,
            grace_timeout: self.grace_timeout,
            recipe: self.recipe,
            bridge,
            state: InjectorState::PreHijack,
            output: None,
            error: None,
        })
    }
}

impl<Driver, T, Bridge> InjectorHandlerAdapter<WindowsOs<Driver>, UserMode, T, Bridge>
    for UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
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

    fn with_grace_timeout(self, timeout: Duration) -> Result<Self, VmiError> {
        Ok(Self {
            grace_timeout: timeout,
            ..self
        })
    }
}

impl<Driver, T, Bridge> UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl,
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
            EventReason::WriteMsr(_) => {
                let _ = self.on_write_msr(vmi);
                Ok(VmiEventResponse::default())
            }
            EventReason::Singlestep(_) => self.on_singlestep(vmi),
            EventReason::Hypercall(_) => self.on_hypercall(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "write_msr", skip_all)]
    fn on_write_msr(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the thread has already been hijacked.
        // (Besides, in such case, this MSR monitoring is being disabled anyway.)
        //

        if !matches!(self.state, InjectorState::PreHijack) {
            return Ok(VmiEventResponse::default());
        }

        //
        // Early exit if the current process is not the target process.
        //

        let current_process = vmi.os().current_process()?;
        let current_pid = current_process.id()?;
        if let Some(pid) = self.pid
            && current_pid != pid
        {
            return Ok(VmiEventResponse::default());
        }

        //
        // Figure out if the current thread is viable for hijacking.
        // First, fetch the current TID and the next instruction from
        // trap frame of the current thread.
        //

        let current_thread = vmi.os().current_thread()?;
        let current_tid = current_thread.id()?;

        let trap_frame = match current_thread.trap_frame()? {
            Some(trap_frame) => trap_frame,
            None => {
                tracing::trace!(%current_tid, "no trap frame");

                return Ok(VmiEventResponse::default());
            }
        };

        let ip_va = trap_frame.instruction_pointer()?;
        let sp_va = trap_frame.stack_pointer()?;

        //
        // Verify that the next instruction of this thread is in a user-mode
        // address space.
        //

        if !vmi.os().is_valid_user_address(ip_va)? {
            tracing::trace!(%ip_va, "skipping invalid pc");

            return Ok(VmiEventResponse::default());
        }

        //
        // Skip a thread that its scheduling group holds back on this
        // processor while the grace period runs. The recipe would wait with
        // the thread, for seconds on a busy guest.
        //

        let prcb = vmi.os().current_kprcb()?;
        if current_thread.is_held_back_by_scheduling_group(&prcb)?
            && self.grace_since.get_or_insert_with(Instant::now).elapsed() < self.grace_timeout
        {
            tracing::trace!(
                %current_pid,
                %current_tid,
                "skipping thread that its scheduling group holds back"
            );

            return Ok(VmiEventResponse::default());
        }

        //
        // Translate the instruction pointer to a physical address.
        //

        let ip_pa = match vmi.translate_address(ip_va) {
            Ok(ip_pa) => {
                tracing::trace!(
                    %current_tid,
                    %sp_va,
                    %ip_va,
                    %ip_pa,
                    "trying to hijack thread"
                );

                ip_pa
            }

            Err(err) => {
                tracing::trace!(
                    %current_tid,
                    %sp_va,
                    %ip_va,
                    ip_pa = "error",
                    "trying to hijack thread"
                );

                return Err(err);
            }
        };

        //
        // If we've tried to hijack a thread before, we need to restore the
        // previous memory access permissions.
        //

        if let Some(previous_ip_pa) = self.ip_pa {
            let previous_ip_gfn = Driver::Architecture::gfn_from_pa(previous_ip_pa);
            vmi.set_memory_access(previous_ip_gfn, self.view, MemoryAccess::RWX)?;
        }

        //
        // Set the memory access permissions for the next user-mode instruction.
        // This will unset the eXecute permission for the page containing the
        // next user-mode instruction. This is necessary to trigger a `MemoryAccess`
        // event when the thread resumes execution.
        //

        let ip_gfn = Driver::Architecture::gfn_from_pa(ip_pa);
        vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RW)?;

        //
        // Mark down the current TID and the VA/PA of the next user-mode instruction.
        // The next `MemoryAccess` handler will try to hijack the thread.
        //

        self.pid = Some(current_pid);
        self.tid = Some(current_tid);
        self.ip_va = Some(ip_va);
        self.ip_pa = Some(ip_pa);

        Ok(VmiEventResponse::default())
    }

    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the memory view is not the target view.
        //

        if vmi.event().view() != Some(self.view) {
            tracing::trace!(
                view = %self.view,
                current_view = %vmi.event().view().unwrap_or(INVALID_VIEW),
                "not the right view"
            );

            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the recipe is no longer executing. An error can end
        // the injection before the view is destroyed.
        //

        if !matches!(
            self.state,
            InjectorState::PreHijack | InjectorState::Executing
        ) {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the current process is not the target process.
        // Note that some physical memory pages (especially those containing
        // mapped files, such as DLLs) are shared among multiple processes.
        // Therefore this event might have been triggered by a different process.
        //

        let current_process = vmi.os().current_process()?;
        let current_pid = current_process.id()?;
        if let Some(pid) = self.pid
            && current_pid != pid
        {
            // Too noisy...
            // tracing::trace!(
            //     pid = %self.pid,
            //     %current_pid,
            //     "not the right process"
            // );
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the current thread is not the target thread.
        //

        let current_thread = vmi.os().current_thread()?;
        let current_tid = current_thread.id()?;
        if Some(current_tid) != self.tid {
            // Too noisy...
            // tracing::trace!(
            //     tid = %self.tid.unwrap_or(INVALID_TID),
            //     %current_tid,
            //     "not the right thread"
            // );
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if this instruction pointer is not the one we're looking for.
        //

        let registers = vmi.registers();
        let ip = Va(registers.rip);
        if Some(ip) != self.ip_va {
            //tracing::trace!(
            //    ip = %self.ip_va.unwrap_or(INVALID_VA),
            //    current_ip = %ip,
            //    "not the right instruction pointer"
            //);

            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Refuse 32-bit processes. The recipe calls functions with the x64
        // calling convention.
        //

        if matches!(self.state, InjectorState::PreHijack)
            && current_process.architecture()? != VmiOsImageArchitecture::Amd64
        {
            return Err(VmiError::Other(
                "injection into 32-bit processes is not supported",
            ));
        }

        //
        // Hijack the thread, save the current registers, and disable MSR monitoring.
        //

        if matches!(self.state, InjectorState::PreHijack) {
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

            let prcb = vmi.os().current_kprcb()?;
            if current_thread.is_held_back_by_scheduling_group(&prcb)? {
                tracing::warn!(
                    %current_pid,
                    %current_tid,
                    "hijacked thread is held back by its scheduling group"
                );
            }

            if !Bridge::EMPTY {
                vmi.monitor_enable(EventMonitor::hypercall().allow_userspace(true))?;
            }

            self.state = InjectorState::Executing;
            vmi.monitor_disable(EventMonitor::msr(Msr::KERNEL_GS_BASE))?;
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
                Err(VmiError::Translation(pf)) => return Err(VmiError::Translation(pf)),
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
        // Terminal path: request exactly one singlestep in the default view
        // with restored registers.
        //
        // Cleanup is intentionally deferred to `on_singlestep`. If the tool
        // exits immediately after this event, monitor teardown may call
        // `xc_monitor_disable` before Xen's vCPU resume path (`hvm_do_resume`)
        // applies staged register changes. The follow-up singlestep event is
        // our rendezvous that the vCPU resumed once past this memory access
        // context, reducing that teardown-ordering race.
        //

        let memory_access = vmi.event().reason().as_memory_access();
        let gfn = Driver::Architecture::gfn_from_pa(memory_access.pa);

        // The GFN of the accessed page should match the GFN of the page we
        // set permissions for in `on_write_msr`.
        debug_assert_eq!(Some(gfn), self.ip_pa.map(Driver::Architecture::gfn_from_pa));

        self.state = InjectorState::Teardown(vmi.event().vcpu_id());

        // The registers must be restored even if this fails. The view is
        // destroyed in `on_singlestep` anyway.
        if let Err(err) = vmi.set_memory_access(gfn, self.view, MemoryAccess::RWX) {
            tracing::error!(%err, "failed to restore memory access");

            if self.error.is_none() {
                self.error = Some(err);
            }
        }

        Ok(VmiEventResponse::singlestep()
            .with_registers(new_registers.gp_registers())
            .with_view(vmi.default_view()))
    }

    #[tracing::instrument(name = "singlestep", skip_all)]
    fn on_singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        // We do not expect any singlestep events until the recipe is done.
        debug_assert!(
            matches!(self.state, InjectorState::Teardown(vcpu) if vcpu == vmi.event().vcpu_id())
        );
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
        vmi.destroy_view(self.view)?;

        if Bridge::EMPTY || self.output.is_some() || self.error.is_some() {
            self.state = InjectorState::Complete;
        }
        else {
            self.state = InjectorState::Bridge;
        }

        Ok(VmiEventResponse::default())
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
    fn on_error(&mut self, err: VmiError) -> VmiEventResponse<Amd64> {
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

        VmiEventResponse::default()
    }
}

impl<Driver, T, Bridge> VmiHandler<WindowsOs<Driver>> for UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
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
            Err(VmiError::Translation(pf)) => {
                tracing::debug!(va = %pf.va, "injecting page fault");
                let _ =
                    vmi.inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(pf.va, 0));

                VmiEventResponse::default()
            }
            Err(err) => self.on_error(err),
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
        // Restored when transitioning from `Executing` to `Teardown`.
        let mut restore_memory_access = false;
        // Destroyed when transitioning from `Teardown` to `Bridge` or `Complete`.
        let mut destroy_view = false;
        // Disabled when transitioning from `PreHijack` to `Executing`.
        let mut disable_write_msr = false;
        // Disabled when transitioning from `Teardown` or `Bridge` to `Complete`.
        let mut disable_hypercall = false;

        match self.state {
            InjectorState::PreHijack | InjectorState::Failed => {
                restore_memory_access = true;
                destroy_view = true;
                disable_write_msr = true;
            }
            InjectorState::Executing => {
                restore_memory_access = true;
                destroy_view = true;
                disable_hypercall = !Bridge::EMPTY;
            }
            InjectorState::Teardown(_) => {
                destroy_view = true;
                disable_hypercall = !Bridge::EMPTY;
            }
            InjectorState::Bridge | InjectorState::Complete => {
                disable_hypercall = !Bridge::EMPTY;
            }
        }

        if restore_memory_access && let Some(ip_pa) = self.ip_pa {
            let ip_gfn = Driver::Architecture::gfn_from_pa(ip_pa);
            if let Err(err) = vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RWX) {
                tracing::error!(%err, "failed to restore memory access");
            }
        }

        if destroy_view {
            if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
                tracing::error!(%err, "failed to switch to default view");
            }

            if let Err(err) = vmi.destroy_view(self.view) {
                tracing::error!(%err, "failed to destroy view");
            }
        }

        if disable_write_msr
            && let Err(err) = vmi.monitor_disable(EventMonitor::msr(Msr::KERNEL_GS_BASE))
        {
            tracing::error!(%err, "failed to disable MSR monitor");
        }

        if disable_hypercall && let Err(err) = vmi.monitor_disable(EventMonitor::hypercall()) {
            tracing::error!(%err, "failed to disable hypercall monitor");
        }

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
