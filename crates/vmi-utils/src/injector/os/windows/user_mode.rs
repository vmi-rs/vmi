use vmi_arch_amd64::{Amd64, ControlRegister, EventMonitor, EventReason, Interrupt};
use vmi_core::{
    Architecture as _, Hex, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext,
    VmiError, VmiEventResponse, VmiHandler, VmiSession,
    driver::{VmiEventControl, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite},
    os::{ProcessId, ThreadId, VmiOsProcess, VmiOsThread},
};
use vmi_os_windows::{WindowsOs, WindowsOsExt as _};

use super::super::super::{
    InjectorHandlerAdapter, InjectorResultCode, Recipe, RecipeExecutor, UserMode,
};
use crate::bridge::{BridgeDispatch, BridgePacket};
// const INVALID_VA: Va = Va(0xffff_ffff_ffff_ffff);
const INVALID_VIEW: View = View(0xffff);
// const INVALID_TID: ThreadId = ThreadId(0xffff_ffff);
// const INVALID_PID: ProcessId = ProcessId(0xffff_ffff);

/// Lifecycle state of the user-mode injector.
enum InjectorState {
    /// Waiting for target process CR3 write; scanning trap frames for
    /// a viable user-mode instruction pointer to hijack.
    PreHijack,
    /// Thread hijacked; executing the injection recipe.
    Executing,
    /// Recipe finished; singlestepping to safely tear down monitoring.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// singlestep event from this specific vCPU signals that it has resumed
    /// past the memory access context, making it safe to tear down monitors
    /// and views.
    Teardown(VcpuId),
    /// Monitoring torn down; waiting for bridge communication.
    Bridge,
    /// Injection complete; result is available.
    Complete(Result<InjectorResultCode, BridgePacket>),
}

pub struct UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiRead<Architecture = Amd64>,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
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

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<WindowsOs<Driver>, T>,

    /// Bridge.
    bridge: Bridge,

    /// Current lifecycle state of the injector.
    state: InjectorState,
}

impl<Driver, T, Bridge> InjectorHandlerAdapter<WindowsOs<Driver>, UserMode, T, Bridge>
    for UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiWrite<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
    Bridge: BridgeDispatch<WindowsOs<Driver>, InjectorResultCode>,
{
    fn with_bridge(
        vmi: &VmiSession<WindowsOs<Driver>>,
        bridge: Bridge,
        recipe: Recipe<WindowsOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;
        vmi.monitor_enable(EventMonitor::Register(ControlRegister::Cr3))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        Ok(Self {
            pid: None,
            tid: None,
            view,
            ip_va: None,
            ip_pa: None,
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

impl<Driver, T, Bridge> UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>,
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
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::WriteControlRegister(_) => {
                let _ = self.on_write_cr(vmi);
                Ok(VmiEventResponse::default())
            }
            EventReason::Singlestep(_) => self.on_singlestep(vmi),
            EventReason::GuestRequest(_) => self.on_vmcall(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "write_cr", skip_all, err)]
    fn on_write_cr(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the thread has already been hijacked.
        // (Besides, in such case, this CR3 monitoring is being disabled anyway.)
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

    #[tracing::instrument(name = "memory_access", skip_all, err)]
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

            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
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
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
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
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
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

            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Hijack the thread, save the current registers, and disable CR3 monitoring.
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
                filename = current_process.name().unwrap_or_else(|_| String::from("<unknown>")),
                "thread hijacked"
            );

            self.state = InjectorState::Executing;
            vmi.monitor_disable(EventMonitor::Register(ControlRegister::Cr3))?;
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
        // set permissions for in `on_write_cr`.
        debug_assert_eq!(Some(gfn), self.ip_pa.map(Driver::Architecture::gfn_from_pa));

        self.state = InjectorState::Teardown(vmi.event().vcpu_id());
        vmi.set_memory_access(gfn, self.view, MemoryAccess::RWX)?;

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
        // We do not expect any singlestep events until the recipe is done.
        debug_assert!(
            matches!(self.state, InjectorState::Teardown(vcpu) if vcpu == vmi.event().vcpu_id())
        );
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
        vmi.destroy_view(self.view)?;

        // If the bridge was not enabled, we're done.
        if Bridge::EMPTY {
            self.state = InjectorState::Complete(Ok(0));
        }
        else {
            self.state = InjectorState::Bridge;
            vmi.monitor_enable(EventMonitor::GuestRequest {
                allow_userspace: true,
            })?;
        }

        Ok(VmiEventResponse::toggle_singlestep())
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
                    allow_userspace: true,
                })?;
            }
        }

        Ok(VmiEventResponse::set_registers(registers))
    }
}

impl<Driver, T, Bridge> VmiHandler<WindowsOs<Driver>> for UserInjectorHandler<Driver, T, Bridge>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
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
        // Restored when transitioning from `Executing` to `Teardown`.
        let mut restore_memory_access = false;
        // Destroyed when transitioning from `Teardown` to `Bridge` or `Complete`.
        let mut destroy_view = false;
        // Disabled when transitioning from `PreHijack` to `Executing`.
        let mut disable_write_cr = false;
        // Disabled when transitioning from `Bridge` to `Complete`.
        let mut disable_guest_request = false;

        match self.state {
            InjectorState::PreHijack => {
                restore_memory_access = true;
                destroy_view = true;
                disable_write_cr = true;
            }
            InjectorState::Executing => {
                restore_memory_access = true;
                destroy_view = true;
            }
            InjectorState::Teardown(_) => {
                destroy_view = true;
            }
            InjectorState::Bridge => {
                disable_guest_request = true;
            }
            _ => {}
        }

        if restore_memory_access && let Some(ip_pa) = self.ip_pa {
            let ip_gfn = Driver::Architecture::gfn_from_pa(ip_pa);
            if let Err(err) = vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RWX) {
                tracing::error!(%err, "failed to restore memory access");
            }
        }

        if destroy_view && let Err(err) = vmi.destroy_view(self.view) {
            tracing::error!(%err, "failed to destroy view");
        }

        if disable_write_cr
            && let Err(err) = vmi.monitor_disable(EventMonitor::Register(ControlRegister::Cr3))
        {
            tracing::error!(%err, "failed to disable CR3 monitor");
        }

        if disable_guest_request
            && let Err(err) = vmi.monitor_disable(EventMonitor::GuestRequest {
                allow_userspace: true,
            })
        {
            tracing::error!(%err, "failed to disable guest request monitor");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
            tracing::error!(%err, "failed to disable singlestep monitor");
        }
    }

    fn check_completion(&self) -> Option<Self::Output> {
        match self.state {
            InjectorState::Complete(result) => Some(result),
            _ => None,
        }
    }
}
