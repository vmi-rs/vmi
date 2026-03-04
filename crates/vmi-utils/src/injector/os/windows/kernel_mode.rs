use vmi_arch_amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt};
use vmi_core::{
    Hex, MemoryAccess, Registers as _, Va, VcpuId, View, VmiContext, VmiError, VmiEventResponse,
    VmiHandler, VmiSession,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryRegisters, VmiRead, VmiSetProtection, VmiViewControl,
        VmiVmControl, VmiWrite,
    },
    os::{ProcessId, ThreadId, VmiOsProcess, VmiOsThread},
};
use vmi_os_windows::{WindowsOs, WindowsOsExt as _};

use super::super::super::{
    InjectorHandlerAdapter, InjectorResultCode, KernelMode, Recipe, RecipeExecutor,
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
    /// Recipe finished; singlestepping to safely tear down monitoring.
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
    Complete(Result<InjectorResultCode, BridgePacket>),
}

pub struct KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
{
    /// Process ID being injected into.
    pid: Option<ProcessId>,

    /// Thread ID that was hijacked for injection.
    tid: Option<ThreadId>,

    /// Memory view used for injection operations.
    view: View,

    /// Breakpoint manager for setting and tracking hijack breakpoints.
    bpm: BreakpointManager<BreakpointController<Driver>>,

    /// Page table monitor for tracking page table modifications.
    ptm: PageTableMonitor<Driver>,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<WindowsOs<Driver>, T>,

    /// Bridge for guest-host communication.
    bridge: Bridge,

    /// Current lifecycle state of the injector.
    state: InjectorState,
}

impl<Driver, T, Bridge> InjectorHandlerAdapter<WindowsOs<Driver>, KernelMode, T, Bridge>
    for KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
{
    /// Creates a new injector handler.
    #[expect(non_snake_case)]
    fn with_bridge(
        vmi: &VmiSession<WindowsOs<Driver>>,
        bridge: Bridge,
        recipe: Recipe<WindowsOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();
        let _pause_guard = vmi.pause_guard()?;

        let registers = vmi.registers(VcpuId(0))?;
        let vmi = vmi.with_registers(&registers);

        let kernel_image_base = vmi.os().kernel_image_base()?;
        tracing::info!(%kernel_image_base);

        let system_process = vmi.os().system_process()?;
        tracing::info!(system_process = %system_process.object()?);

        let root = system_process.translation_root()?;
        tracing::info!(%root);

        // SeAccessCheck is chosen because it is one of the most frequently called
        // functions in the Windows kernel, so a hijack breakpoint here is almost
        // immediately hit. It also runs at PASSIVE_LEVEL, which means paged memory
        // is accessible and we can safely read/write memory without worrying about
        // IRQL issues.
        let va_SeAccessCheck = kernel_image_base + vmi.os().symbols().SeAccessCheck.unwrap();
        let cx_SeAccessCheck = (va_SeAccessCheck, root);
        let bp_SeAccessCheck = Breakpoint::new(cx_SeAccessCheck, view)
            .global()
            .with_tag("SeAccessCheck");
        bpm.insert(&vmi, bp_SeAccessCheck)?;
        ptm.monitor(&vmi, cx_SeAccessCheck, view, "SeAccessCheck")?;
        tracing::info!(%va_SeAccessCheck);

        Ok(Self {
            pid: None,
            tid: None,
            view,
            bpm,
            ptm,
            recipe: RecipeExecutor::new(recipe),
            bridge,
            state: InjectorState::PreHijack,
        })
    }

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
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
{
    #[tracing::instrument(
        name = "injector",
        skip_all,
        err,
        fields(
            vcpu = %vmi.event().vcpu_id(),
            rip = %Va(vmi.registers().rip),
        )
    )]
    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        tracing::trace!(reason = ?vmi.event().reason(), "handling event");
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::Interrupt(_) => self.on_interrupt(vmi),
            EventReason::Singlestep(_) => self.on_singlestep(vmi),
            EventReason::GuestRequest(_) => self.on_vmcall(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "memory_access", skip_all, err)]
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

            Ok(VmiEventResponse::toggle_singlestep().and_set_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            // When the guest tries to read from the memory, a fast-singlestep
            // is performed over the instruction that tried to read the memory.
            // This is done to allow the instruction to read the original memory
            // content.
            Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()))
        }
        else {
            panic!("Unhandled memory access: {memory_access:?}");
        }
    }

    #[tracing::instrument(name = "interrupt", skip_all, err)]
    fn on_interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match self.bpm.get_by_event(vmi.event(), ()) {
            Some(breakpoints) => {
                // Breakpoints can have multiple tags, but we have set only one
                // tag for each breakpoint.
                let first_breakpoint = breakpoints.into_iter().next().expect("breakpoint");
                debug_assert_eq!(first_breakpoint.tag(), "SeAccessCheck");
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    // This breakpoint was not set by us. Reinject it.
                    tracing::warn!("Unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                else {
                    // We have received a breakpoint event, but there is no
                    // breakpoint instruction at the current memory location.
                    // This can happen if the event was triggered by a breakpoint
                    // we just removed.
                    tracing::warn!("Ignoring old breakpoint event");
                    return Ok(
                        VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view())
                    );
                }
            }
        };

        let current_process = vmi.os().current_process()?;

        //
        // Skip processes without a PEB.
        //
        // We want to avoid injecting into processes like "Registry" or
        // "MemCompression", because the functions called in the shellcode
        // would likely fail with access violations.
        //

        if current_process.peb()?.is_none() {
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        let current_pid = current_process.id()?;

        if self.pid.is_none() {
            tracing::trace!(%current_pid, "hijacking process");
            self.pid = Some(current_pid);
        }
        else if Some(current_pid) != self.pid {
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        let current_thread = vmi.os().current_thread()?;
        let current_tid = current_thread.id()?;

        if self.tid.is_none() {
            self.tid = Some(current_tid);
            self.state = InjectorState::Executing;
            tracing::debug!(
                session_id = current_process
                    .session()
                    .ok()
                    .flatten()
                    .and_then(|session| session.id().ok())
                    .unwrap_or(0),
                %current_pid,
                %current_tid,
                filename = current_process.name().unwrap_or_else(|_| String::from("<unknown>")),
                "thread hijacked"
            );
        }
        else if Some(current_tid) != self.tid {
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Execute the next step in the recipe.
        //

        let new_registers = match self.recipe.execute(vmi)? {
            Some(registers) => registers,
            None => {
                return Ok(
                    VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view())
                );
            }
        };

        if !self.recipe.done() {
            return Ok(VmiEventResponse::set_registers(
                new_registers.gp_registers(),
            ));
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

        Ok(
            VmiEventResponse::set_registers(new_registers.gp_registers())
                .and_toggle_singlestep()
                .and_set_view(vmi.default_view()),
        )
    }

    #[tracing::instrument(name = "singlestep", skip_all, err)]
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
            // on every vCPU, clearing per-vCPU `single_step` state. The response's
            // `toggle_singlestep` then flips it back to true on this vCPU, but
            // with global singlestep delivery already off, the resulting MTF exits
            // are silently discarded and `single_step` is never cleared - trapping
            // the vCPU in an infinite MTF loop with interrupt injection blocked.
            vmi.switch_to_view(vmi.default_view())?;
            vmi.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;

            self.bpm.remove_by_view(vmi, self.view)?;
            self.ptm.unmonitor_view(vmi, self.view);

            vmi.destroy_view(self.view)?;

            // If the bridge was not enabled, we're done.
            if Bridge::EMPTY {
                self.state = InjectorState::Complete(Ok(0));
            }
            else {
                self.state = InjectorState::Bridge;
                vmi.monitor_enable(EventMonitor::GuestRequest {
                    allow_userspace: false,
                })?;
            }

            return Ok(VmiEventResponse::toggle_singlestep());
        }

        // Get the page table modifications by processing the dirty page table
        // entries.
        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, ptm_events)?;

        // Disable singlestep and switch back to our view.
        Ok(VmiEventResponse::toggle_singlestep().and_set_view(self.view))
    }

    #[tracing::instrument(name = "vmcall", skip_all, err)]
    fn on_vmcall(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let guest_request = vmi.event().reason().as_guest_request();

        let mut registers = vmi.registers().gp_registers();
        registers.rip += guest_request.instruction_length as u64;

        tracing::trace!(
            magic = %Hex(registers.rbp as u32),
            request = %Hex((registers.rcx & 0xFFFF) as u16),
            method = %Hex((registers.rcx >> 16) as u16),
        );

        if let Some(result) = self.bridge.dispatch(vmi, BridgePacket::from(vmi)) {
            let complete = match result {
                Ok(response) => {
                    response.write_to(&mut registers);
                    response.into_result().map(Ok)
                }
                Err(packet) => {
                    tracing::error!(
                        request = packet.request(),
                        method = packet.method(),
                        "Empty bridge response"
                    );
                    Some(Err(packet))
                }
            };

            if let Some(complete) = complete {
                self.state = InjectorState::Complete(complete);
                vmi.monitor_disable(EventMonitor::GuestRequest {
                    allow_userspace: false,
                })?;
            }
        }

        Ok(VmiEventResponse::set_registers(registers))
    }
}

impl<Driver, T, Bridge> VmiHandler<WindowsOs<Driver>> for KernelInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiDriver<Architecture = Amd64>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
{
    type Output = Result<InjectorResultCode, BridgePacket>;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,
            Err(VmiError::Translation(pfs)) => {
                let pf = pfs[0];

                tracing::debug!(?pf, "injecting page fault");
                let _ =
                    vmi.inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(pf.va, 0));

                VmiEventResponse::default()
            }
            Err(err) => panic!("Unhandled error: {err:?}"),
        }
    }

    fn cleanup(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        // Disabled when transitioning from `Teardown` to `Bridge` or `Complete`.
        let mut disable_interrupt = false;
        // Disabled when transitioning from `Bridge` to `Complete`.
        let mut disable_guest_request = false;

        match self.state {
            InjectorState::PreHijack | InjectorState::Executing | InjectorState::Teardown(_) => {
                disable_interrupt = true;
            }
            InjectorState::Bridge => {
                disable_guest_request = true;
            }
            _ => {}
        }

        // In `PreHijack`, `Executing`, or `Teardown` states, we are guaranteed to
        // have enabled the breakpoint monitor, so we must disable it.
        if disable_interrupt {
            if let Err(err) =
                vmi.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))
            {
                tracing::error!(%err, "failed to disable breakpoint monitor");
            }

            if let Err(err) = self.bpm.remove_by_view(vmi, self.view) {
                tracing::error!(%err, "failed to remove breakpoints");
            }

            self.ptm.unmonitor_view(vmi, self.view);

            if let Err(err) = vmi.destroy_view(self.view) {
                tracing::error!(%err, "failed to destroy view");
            }
        }

        // In `Bridge` state, we are guaranteed to have enabled the guest request
        // monitor, so we must disable it.
        if disable_guest_request
            && let Err(err) = vmi.monitor_disable(EventMonitor::GuestRequest {
                allow_userspace: false,
            })
        {
            tracing::error!(%err, "failed to disable guest request monitor");
        }

        // In all states, we are guaranteed to have enabled the singlestep
        // monitor, so we must disable it.
        if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
            tracing::error!(%err, "failed to disable singlestep monitor");
        }
    }

    fn poll(&self) -> Option<Self::Output> {
        match self.state {
            InjectorState::Complete(result) => Some(result),
            _ => None,
        }
    }
}
