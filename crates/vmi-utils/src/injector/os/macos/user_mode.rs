use std::ops::ControlFlow;

use vmi_arch_arm64::{Arm64, EventMonitor, EventReason, Granule16KVa47, Interrupt, SystemRegister};
use vmi_core::{
    Architecture as _, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    driver::{
        VmiDriver, VmiEventControl, VmiRead, VmiSetProtection, VmiViewControl, VmiVmControl,
        VmiWrite,
    },
    os::{ProcessId, ThreadObject, VmiOsImageArchitecture, VmiOsProcess as _, VmiOsThread as _},
};
use vmi_os_macos::{ArchAdapter as MacOsArchAdapter, MacOs};

use super::super::super::{
    BridgeDispatch, InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory,
    Recipe, RecipeExecutor, UserMode,
};

/// Architecture of a macOS guest.
type Arch = Arm64<Granule16KVa47>;

/// Encoding of the `SVC` instruction without its immediate.
const SVC: u32 = 0xd400_0001;

/// Mask of the bits of the `SVC` instruction that do not hold its immediate.
const SVC_MASK: u32 = 0xffe0_001f;

/// Size of an arm64 instruction, in bytes.
const INSTRUCTION_SIZE: u64 = 4;

/// Lifecycle state of the user-mode injector.
enum InjectorState {
    /// Waiting for a thread of the target process to return from a syscall.
    PreHijack,

    /// Thread hijacked, executing the injection recipe.
    Executing,

    /// Recipe finished or aborted, single-stepping the original instruction
    /// before the view is destroyed.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// single-step event from this vCPU shows that it is past the memory
    /// access.
    Teardown(VcpuId),

    /// Injection complete, the result is available.
    Complete,

    /// Injection failed before the hijack, the error is available.
    Failed,
}

/// User-mode injector for macOS on Apple silicon.
///
/// The injector watches context switches through writes to `TTBR0_EL1`.
/// When a thread of the target process waits in the kernel to resume right
/// after an `SVC` instruction, the injector removes execute permission from
/// the page that holds this instruction, in a view of its own. The thread
/// faults when it returns from the syscall, and the injector then runs the
/// recipe on it, one injected call per return.
///
/// # Notes
///
/// The injector restores only the general-purpose registers of the hijacked
/// thread. It hijacks a thread only where a syscall stub returns, because the
/// caller of the stub keeps no value in the caller-saved registers, the SIMD
/// registers among them, which the injected calls may change.
pub struct UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch> + VmiRead,
{
    /// Process ID being injected into.
    pid: Option<ProcessId>,

    /// Thread that is hijacked, or waited for.
    thread: Option<ThreadObject>,

    /// Memory view used for injection operations.
    view: View,

    /// Whether the view is destroyed.
    ///
    /// A vCPU can hold the view for a moment after the switch to the default
    /// view, and `cleanup` then destroys it.
    view_destroyed: bool,

    /// Virtual address of the instruction where the thread resumes.
    ip_va: Option<Va>,

    /// Physical address of the instruction where the thread resumes.
    ip_pa: Option<Pa>,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<MacOs<Driver>, T>,

    /// Current lifecycle state of the injector.
    state: InjectorState,

    /// Error that ended the injection.
    error: Option<VmiError>,
}

impl<Driver, T> InjectorHandlerFactory<MacOs<Driver>, UserMode, T>
    for UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    fn new(
        vmi: &VmiSession<MacOs<Driver>>,
        recipe: Recipe<MacOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        vmi.monitor_enable(EventMonitor::Register(SystemRegister::Ttbr0El1))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        Ok(Self {
            pid: None,
            thread: None,
            view,
            view_destroyed: false,
            ip_va: None,
            ip_pa: None,
            recipe: RecipeExecutor::new(recipe),
            state: InjectorState::PreHijack,
            error: None,
        })
    }

    /// Fails with [`VmiError::NotSupported`], because macOS has no bridge.
    fn with_bridge<Bridge>(
        self,
        _bridge: Bridge,
    ) -> Result<<MacOs<Driver> as InjectorExecutionAdapter<UserMode, T, Bridge>>::Handler, VmiError>
    where
        Bridge: BridgeDispatch<MacOs<Driver>>,
        MacOs<Driver>: InjectorExecutionAdapter<UserMode, T, Bridge>,
    {
        Err(VmiError::NotSupported)
    }
}

impl<Driver, T> InjectorHandlerAdapter<MacOs<Driver>, UserMode, T, ()>
    for UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    fn with_pid(self, pid: ProcessId) -> Result<Self, VmiError> {
        Ok(Self {
            pid: Some(pid),
            ..self
        })
    }
}

impl<Driver, T> UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl,
{
    #[tracing::instrument(
        name = "injector",
        skip_all,
        fields(
            vcpu = %vmi.event().vcpu_id(),
            pc = %Va(vmi.registers().pc),
        )
    )]
    fn dispatch(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::WriteSystemRegister(_) => {
                if let Err(err) = self.on_write_system_register(vmi) {
                    tracing::trace!(%err, "thread not armed");
                }

                Ok(VmiEventResponse::default())
            }
            EventReason::Singlestep(_) => Ok(self.on_singlestep(vmi)),
            EventReason::Interrupt(_) => Ok(VmiEventResponse::default()),
        }
    }

    /// Arms the thread running on the CPU when it belongs to the target
    /// process and resumes right after an `SVC` instruction.
    ///
    /// An armed thread replaces the one armed before.
    #[tracing::instrument(name = "write_system_register", skip_all)]
    fn on_write_system_register(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<(), VmiError> {
        if !matches!(self.state, InjectorState::PreHijack) {
            return Ok(());
        }

        let current_thread = vmi.os().current_thread()?;
        let current_process = match current_thread.attached_process()? {
            Some(current_process) => current_process,
            None => return Ok(()),
        };

        let current_pid = current_process.id()?;
        if let Some(pid) = self.pid
            && current_pid != pid
        {
            return Ok(());
        }

        let saved_state = match current_thread.user_saved_state()? {
            Some(saved_state) => saved_state,
            None => return Ok(()),
        };

        let ip_va = saved_state.instruction_pointer()?;
        if ip_va.is_null() || <Arch as MacOsArchAdapter<Driver>>::is_kernel_address(ip_va) {
            return Ok(());
        }

        //
        // The thread must resume where a syscall returns. The caller-saved
        // registers hold nothing there that the injected calls could destroy.
        //

        let root = current_process.translation_root()?;
        let instruction = vmi.read_u32_in((ip_va - INSTRUCTION_SIZE, root))?;
        if instruction & SVC_MASK != SVC {
            return Ok(());
        }

        let current_thread_object = current_thread.object()?;
        if self.thread == Some(current_thread_object) && self.ip_va == Some(ip_va) {
            return Ok(());
        }

        let ip_pa = vmi.core().translate_address((ip_va, root))?;
        let ip_gfn = Arch::gfn_from_pa(ip_pa);

        //
        // Restore the access of the page armed before, unless it is the page
        // armed now.
        //

        if let Some(previous_ip_pa) = self.ip_pa {
            let previous_ip_gfn = Arch::gfn_from_pa(previous_ip_pa);
            if previous_ip_gfn != ip_gfn {
                vmi.set_memory_access(previous_ip_gfn, self.view, MemoryAccess::RWX)?;
            }
        }

        //
        // Remove the execute permission from the page, so the thread raises
        // a memory access event when it returns from the syscall.
        //

        vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RW)?;

        tracing::trace!(
            %current_pid,
            thread = %current_thread_object,
            %ip_va,
            %ip_pa,
            "thread armed"
        );

        self.pid = Some(current_pid);
        self.thread = Some(current_thread_object);
        self.ip_va = Some(ip_va);
        self.ip_pa = Some(ip_pa);

        Ok(())
    }

    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
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
        // Early exit if the current thread is not the armed thread, or if
        // this instruction is not the one it resumes at. Every process runs
        // code from the shared pages of the system libraries.
        //

        let current_thread = vmi.os().current_thread()?;
        if Some(current_thread.object()?) != self.thread
            || Some(Va(vmi.registers().pc)) != self.ip_va
        {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Hijack the thread and disable the monitoring of context switches.
        //

        if matches!(self.state, InjectorState::PreHijack) {
            let current_process = current_thread.process()?;
            let current_pid = current_process.id()?;

            // The kernel reuses the memory of an exited thread.
            if Some(current_pid) != self.pid {
                return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
            }

            // The recipe calls functions with the arm64 calling convention.
            if current_process.architecture()? != VmiOsImageArchitecture::Arm64 {
                return Err(VmiError::Other(
                    "injection into processes that are not arm64 is not supported",
                ));
            }

            tracing::debug!(
                %current_pid,
                thread_id = current_thread.thread_id()?,
                name = current_process.name().as_deref().unwrap_or("<unknown>"),
                "thread hijacked"
            );

            self.state = InjectorState::Executing;
            vmi.monitor_disable(EventMonitor::Register(SystemRegister::Ttbr0El1))?;
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
            Some(new_registers) => new_registers,
            None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
        };

        if self.error.is_none() && !self.recipe.done() {
            return Ok(VmiEventResponse::default().with_registers(new_registers.gp_registers()));
        }

        //
        // Terminal path: single-step the original instruction in the default
        // view with the original registers. The single-step event that
        // follows shows that the vCPU is past this memory access, and the
        // view is destroyed there.
        //

        self.state = InjectorState::Teardown(vmi.event().vcpu_id());

        // The registers must be restored even if this fails. The view is
        // destroyed in `on_singlestep` anyway.
        if let Some(ip_pa) = self.ip_pa
            && let Err(err) =
                vmi.set_memory_access(Arch::gfn_from_pa(ip_pa), self.view, MemoryAccess::RWX)
        {
            tracing::error!(%err, "failed to restore memory access");

            if self.error.is_none() {
                self.error = Some(err);
            }
        }

        Ok(VmiEventResponse::singlestep()
            .with_registers(new_registers.gp_registers())
            .with_view(vmi.default_view()))
    }

    /// Switches every vCPU to the default view and destroys the view, once
    /// the vCPU that completed the recipe has single-stepped the original
    /// instruction.
    #[tracing::instrument(name = "singlestep", skip_all)]
    fn on_singlestep(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        if !matches!(self.state, InjectorState::Teardown(vcpu) if vcpu == vmi.event().vcpu_id()) {
            return VmiEventResponse::default();
        }

        // Single-step monitoring stays enabled until `cleanup`. The response
        // without the single-step action stops stepping this vCPU.
        if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
            tracing::error!(%err, "failed to switch to default view");

            if self.error.is_none() {
                self.error = Some(err);
            }
        }

        match vmi.destroy_view(self.view) {
            Ok(()) => self.view_destroyed = true,
            Err(err) => tracing::debug!(%err, "view still in use, destroying it at cleanup"),
        }

        self.state = InjectorState::Complete;
        VmiEventResponse::default()
    }

    /// Records `err` as the error that ends the injection.
    ///
    /// Before the hijack, the injection ends at once. While the recipe is
    /// executing, it ends once the hijacked thread has its original registers
    /// back.
    fn on_error(&mut self, err: VmiError) -> VmiEventResponse<Arch> {
        tracing::error!(%err, "injection failed");

        if self.error.is_none() {
            self.error = Some(err);
        }

        if matches!(self.state, InjectorState::PreHijack) {
            self.state = InjectorState::Failed;
        }

        VmiEventResponse::default()
    }
}

impl<Driver, T> VmiHandler<MacOs<Driver>> for UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    type Output = Result<(), VmiError>;

    fn handle_event(&mut self, vmi: VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,

            // A recipe step read or wrote a user page that is not resident.
            // The hijacked thread pages it in and returns to the same
            // instruction, which repeats the step.
            Err(VmiError::Translation(pf))
                if !<Arch as MacOsArchAdapter<Driver>>::is_kernel_address(pf.va) =>
            {
                tracing::debug!(va = %pf.va, "injecting page fault");

                if let Err(err) =
                    vmi.inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(pf.va.0))
                {
                    return self.on_error(err);
                }

                VmiEventResponse::default()
            }
            Err(err) => self.on_error(err),
        }
    }

    fn handle_interrupted(&mut self, _vmi: &VmiSession<MacOs<Driver>>) -> ControlFlow<()> {
        let flow = match self.state {
            InjectorState::Complete | InjectorState::Failed => return ControlFlow::Break(()),

            // The guest is still unchanged.
            InjectorState::PreHijack => {
                self.state = InjectorState::Failed;
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

    fn cleanup(&mut self, vmi: &VmiSession<MacOs<Driver>>) {
        // Restored when transitioning from `Executing` to `Teardown`.
        let restore_memory_access = matches!(
            self.state,
            InjectorState::PreHijack | InjectorState::Failed | InjectorState::Executing
        );
        // Disabled when transitioning from `PreHijack` to `Executing`.
        let disable_ttbr0 = matches!(self.state, InjectorState::PreHijack | InjectorState::Failed);

        if restore_memory_access && let Some(ip_pa) = self.ip_pa {
            let ip_gfn = Arch::gfn_from_pa(ip_pa);
            if let Err(err) = vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RWX) {
                tracing::error!(%err, "failed to restore memory access");
            }
        }

        if !self.view_destroyed {
            if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
                tracing::error!(%err, "failed to switch to default view");
            }

            if let Err(err) = vmi.destroy_view(self.view) {
                tracing::error!(%err, "failed to destroy view");
            }
        }

        if disable_ttbr0
            && let Err(err) = vmi.monitor_disable(EventMonitor::Register(SystemRegister::Ttbr0El1))
        {
            tracing::error!(%err, "failed to disable TTBR0_EL1 monitor");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
            tracing::error!(%err, "failed to disable singlestep monitor");
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        match self.state {
            InjectorState::Complete | InjectorState::Failed => match self.error.take() {
                Some(err) => Some(Err(err)),
                None => Some(Ok(())),
            },
            _ => None,
        }
    }
}
