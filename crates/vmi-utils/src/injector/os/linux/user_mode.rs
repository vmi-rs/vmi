use std::ops::ControlFlow;

use vmi_arch_amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt};
use vmi_core::{
    Architecture as _, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    arch::Interrupt as _,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead,
        VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    },
    os::{ProcessId, ThreadId, VmiOsImageArchitecture, VmiOsProcess as _, VmiOsThread as _},
    trace::Hex,
};
use vmi_os_linux::LinuxOs;

use super::super::super::{
    InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory, Recipe,
    RecipeExecutor, UserMode,
};
use crate::{
    bpm::{Breakpoint, BreakpointController, BreakpointManager},
    bridge::{BridgeDispatch, BridgePacket},
    ptm::PageTableMonitor,
};

/// Lifecycle state of the user-mode injector.
enum InjectorState {
    /// Waiting for a thread of the target process to return from a syscall
    /// to the address that the execute trap watches.
    PreHijack,

    /// The thread is hijacked and executes the injection recipe.
    Executing,

    /// The recipe finished or aborted, and a singlestep tears down the
    /// monitoring safely.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// singlestep event from this specific vCPU signals that it runs past
    /// the memory access context again, which makes it safe to tear down
    /// monitors and views. Singlestep events from other vCPUs are unrelated
    /// page table monitor activity and must not trigger teardown.
    Teardown(VcpuId),

    /// The monitoring is torn down, and the injector waits for bridge
    /// communication.
    Bridge,

    /// The injection is complete, and its result is available.
    Complete,

    /// The injection failed before the hijack, and its error is available.
    Failed,
}

pub struct UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<LinuxOs<Driver>>,
{
    /// Process ID being injected into.
    pid: Option<ProcessId>,

    /// Thread ID that was hijacked for injection.
    tid: Option<ThreadId>,

    /// Memory view used for injection operations.
    view: View,

    /// Breakpoint manager for the breakpoint at `x64_sys_call`.
    bpm: BreakpointManager<LinuxOs<Driver>, BreakpointController<Driver>>,

    /// Page table monitor for tracking page table modifications.
    ptm: PageTableMonitor<Driver>,

    /// Virtual address where the chosen thread returns to user mode.
    ip_va: Option<Va>,

    /// Physical address of `ip_va`, whose page the execute trap watches.
    ip_pa: Option<Pa>,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<LinuxOs<Driver>, T>,

    /// Bridge for guest-host communication.
    bridge: Bridge,

    /// Current lifecycle state of the injector.
    state: InjectorState,

    /// Output produced by the bridge.
    output: Option<Result<Bridge::Output, BridgePacket>>,

    /// Error that ended the injection.
    error: Option<VmiError>,
}

impl<Driver, T> InjectorHandlerFactory<LinuxOs<Driver>, UserMode, T>
    for UserInjectorHandler<Driver, T, ()>
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
    fn new(
        vmi: &VmiSession<LinuxOs<Driver>>,
        recipe: Recipe<LinuxOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        vmi.monitor_enable(EventMonitor::interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::singlestep())?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();

        let paused = vmi.pause_guard()?;
        let vmi = paused.state();

        let system_process = vmi.os().system_process()?;
        let root = system_process.translation_root()?;

        // Every 64-bit syscall from user mode passes x64_sys_call. There the
        // handler learns where the thread returns to user mode, and it sets
        // the execute trap on that page.
        let x64_sys_call = LinuxOs::symbols(vmi)
            .x64_sys_call
            .ok_or(VmiError::Other("x64_sys_call not found"))?;
        let va_x64_sys_call = LinuxOs::symbol_address(vmi, x64_sys_call)?;
        let cx_x64_sys_call = (va_x64_sys_call, root);
        let bp_x64_sys_call = Breakpoint::new(cx_x64_sys_call, view)
            .global()
            .with_tag("x64_sys_call");
        bpm.insert(&vmi, bp_x64_sys_call)?;
        ptm.monitor(&vmi, cx_x64_sys_call, view, "x64_sys_call")?;

        Ok(Self {
            pid: None,
            tid: None,
            view,
            bpm,
            ptm,
            ip_va: None,
            ip_pa: None,
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
    ) -> Result<<LinuxOs<Driver> as InjectorExecutionAdapter<UserMode, T, Bridge>>::Handler, VmiError>
    where
        Bridge: BridgeDispatch<LinuxOs<Driver>>,
    {
        Ok(UserInjectorHandler {
            pid: self.pid,
            tid: self.tid,
            view: self.view,
            bpm: self.bpm,
            ptm: self.ptm,
            ip_va: self.ip_va,
            ip_pa: self.ip_pa,
            recipe: self.recipe,
            bridge,
            state: InjectorState::PreHijack,
            output: None,
            error: None,
        })
    }
}

impl<Driver, T, Bridge> InjectorHandlerAdapter<LinuxOs<Driver>, UserMode, T, Bridge>
    for UserInjectorHandler<Driver, T, Bridge>
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
    Bridge: BridgeDispatch<LinuxOs<Driver>>,
{
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError> {
        Ok(Self {
            pid: Some(pid),
            ..self
        })
    }
}

impl<Driver, T, Bridge> UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<LinuxOs<Driver>>,
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
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::Interrupt(_) => self.on_interrupt(vmi),
            EventReason::Singlestep(_) => self.on_singlestep(vmi),
            EventReason::Hypercall(_) => self.on_hypercall(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "interrupt", skip_all)]
    fn on_interrupt(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match self.bpm.get_by_event(vmi, vmi.event(), ()) {
            Some(breakpoint) => {
                debug_assert_eq!(breakpoint.tag(), "x64_sys_call");
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    // This breakpoint was not set by us. Reinject it.
                    tracing::warn!("unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                else {
                    // A breakpoint event arrived, but no breakpoint
                    // instruction is at the current memory location. A
                    // breakpoint that we just removed can cause this.
                    tracing::warn!("ignoring old breakpoint event");
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }
            }
        };

        //
        // The thread runs in the kernel here. An error skips the thread, and
        // a page fault never goes to the guest.
        //

        if matches!(self.state, InjectorState::PreHijack)
            && let Err(err) = self.set_trap(vmi)
        {
            tracing::trace!(%err, "skipping thread");
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    /// Moves the execute trap to the address where the current thread
    /// returns to user mode.
    ///
    /// At `x64_sys_call`, `rdi` points to the `pt_regs` of the syscall.
    /// `pt_regs.ip` holds the address after the thread's `syscall`
    /// instruction.
    fn set_trap(&mut self, vmi: &VmiContext<LinuxOs<Driver>>) -> Result<(), VmiError> {
        let current_process = vmi.os().current_process()?;
        let current_pid = current_process.id()?;
        if let Some(pid) = self.pid
            && current_pid != pid
        {
            return Ok(());
        }

        let current_tid = vmi.os().current_thread()?.id()?;

        let pt_regs = &LinuxOs::offsets(**vmi).pt_regs;
        let ip_va = vmi.read_va64(Va(vmi.registers().rdi) + pt_regs.ip.offset())?;

        if Amd64::is_kernel_address(ip_va) {
            return Err(VmiError::Other("the syscall returns to a kernel address"));
        }

        let ip_pa = vmi.translate_address(ip_va)?;

        //
        // If we've tried to hijack a thread before, we need to restore the
        // previous memory access permissions.
        //

        if let Some(previous_ip_pa) = self.ip_pa {
            let previous_ip_gfn = Amd64::gfn_from_pa(previous_ip_pa);
            vmi.set_memory_access(previous_ip_gfn, self.view, MemoryAccess::RWX)?;
        }

        //
        // Unset the eXecute permission for the page with the return address.
        // The thread triggers a `MemoryAccess` event when it returns there.
        //

        let ip_gfn = Amd64::gfn_from_pa(ip_pa);
        vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RW)?;

        tracing::trace!(%current_pid, %current_tid, %ip_va, %ip_pa, "trap set");

        self.pid = Some(current_pid);
        self.tid = Some(current_tid);
        self.ip_va = Some(ip_va);
        self.ip_pa = Some(ip_pa);

        Ok(())
    }

    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        if memory_access.access.contains(MemoryAccess::X) {
            self.on_execute(vmi)
        }
        else if memory_access.access.contains(MemoryAccess::W) {
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

    /// Handles an instruction fetch from the page of the execute trap.
    fn on_execute(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the memory view is not the target view, or if the
        // recipe is no longer executing. An error can end the injection
        // before the view is destroyed.
        //

        if vmi.event().view() != Some(self.view)
            || !matches!(
                self.state,
                InjectorState::PreHijack | InjectorState::Executing
            )
        {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the current process is not the target process. The
        // pages of a library are shared among processes, and another process
        // can trigger this event.
        //

        let current_process = vmi.os().current_process()?;
        let current_pid = current_process.id()?;
        if let Some(pid) = self.pid
            && current_pid != pid
        {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the current thread is not the target thread, or if
        // this instruction pointer is not the one we're looking for.
        //

        let current_tid = vmi.os().current_thread()?.id()?;
        if Some(current_tid) != self.tid || Some(Va(vmi.registers().rip)) != self.ip_va {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Hijack the thread. The breakpoint at x64_sys_call is no longer
        // needed.
        //

        if matches!(self.state, InjectorState::PreHijack) {
            // Refuse 32-bit processes. The recipe calls functions with the
            // System V calling convention of x86-64.
            if current_process.architecture()? != VmiOsImageArchitecture::Amd64 {
                return Err(VmiError::Other(
                    "injection into 32-bit processes is not supported",
                ));
            }

            tracing::debug!(
                %current_pid,
                %current_tid,
                filename = current_process
                    .name()
                    .as_deref()
                    .unwrap_or("<unknown>"),
                "thread hijacked"
            );

            self.bpm.remove_by_view(vmi, self.view)?;
            self.ptm.unmonitor_view(vmi, self.view);

            if !Bridge::EMPTY {
                vmi.monitor_enable(EventMonitor::hypercall().allow_userspace(true))?;
            }

            self.state = InjectorState::Executing;
        }

        //
        // Execute the next step in the recipe. After an error, abort the
        // recipe instead. The hijacked thread then resumes with its original
        // registers. A page fault goes to the guest, and the step runs again
        // after the guest handles it.
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
        let gfn = Amd64::gfn_from_pa(memory_access.pa);

        // The accessed page should be the page whose permissions `set_trap`
        // changed.
        debug_assert_eq!(Some(gfn), self.ip_pa.map(Amd64::gfn_from_pa));

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
        vmi: &VmiContext<LinuxOs<Driver>>,
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
        vmi: &VmiContext<LinuxOs<Driver>>,
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
        vmi: &VmiContext<LinuxOs<Driver>>,
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
        // back keeps the execute trap in place for the hijacked thread, which
        // must still get its original registers back.
        match vmi.event().reason() {
            EventReason::Singlestep(_) if matches!(self.state, InjectorState::Executing) => {
                VmiEventResponse::default().with_view(self.view)
            }
            _ => VmiEventResponse::default(),
        }
    }
}

impl<Driver, T, Bridge> VmiHandler<LinuxOs<Driver>> for UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<LinuxOs<Driver>>,
{
    type Output = Result<Option<Result<Bridge::Output, BridgePacket>>, VmiError>;

    fn handle_event(&mut self, vmi: VmiContext<LinuxOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,

            // A page fault on a user address, in a vCPU that runs in user
            // mode, goes to the guest. The kernel maps the page, copies a
            // shared one or sets the dirty bit, and the step runs again.
            Err(VmiError::PageFault(pf))
                if !Amd64::is_kernel_address(pf.va)
                    && !Amd64::is_kernel_address(Va(vmi.registers().rip)) =>
            {
                tracing::debug!(?pf, "injecting page fault");
                let _ = vmi.inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(pf));

                VmiEventResponse::default()
            }

            Err(err) => self.on_error(&vmi, err),
        }
    }

    fn handle_interrupted(&mut self, _vmi: &VmiSession<LinuxOs<Driver>>) -> ControlFlow<()> {
        let flow = match self.state {
            InjectorState::Complete | InjectorState::Failed => return ControlFlow::Break(()),

            // The guest is still as it was.
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

    fn cleanup(&mut self, vmi: &VmiSession<LinuxOs<Driver>>) {
        // Restored when transitioning from `Executing` to `Teardown`.
        let mut restore_memory_access = false;
        // Disabled when transitioning from `Teardown` to `Bridge` or `Complete`.
        let mut disable_interrupt = false;
        // Disabled when transitioning from `Teardown` or `Bridge` to `Complete`.
        let mut disable_hypercall = false;

        match self.state {
            InjectorState::PreHijack | InjectorState::Failed => {
                restore_memory_access = true;
                disable_interrupt = true;
            }
            InjectorState::Executing => {
                restore_memory_access = true;
                disable_interrupt = true;
                disable_hypercall = !Bridge::EMPTY;
            }
            InjectorState::Teardown(_) => {
                disable_interrupt = true;
                disable_hypercall = !Bridge::EMPTY;
            }
            InjectorState::Bridge | InjectorState::Complete => {
                disable_hypercall = !Bridge::EMPTY;
            }
        }

        if restore_memory_access && let Some(ip_pa) = self.ip_pa {
            let ip_gfn = Amd64::gfn_from_pa(ip_pa);
            if let Err(err) = vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RWX) {
                tracing::error!(%err, "failed to restore memory access");
            }
        }

        // Until `Teardown` ends, the breakpoint monitor is enabled and the
        // view exists.
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

        if disable_hypercall && let Err(err) = vmi.monitor_disable(EventMonitor::hypercall()) {
            tracing::error!(%err, "failed to disable hypercall monitor");
        }

        // The singlestep monitor is enabled in every state and needs to be
        // disabled.
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
