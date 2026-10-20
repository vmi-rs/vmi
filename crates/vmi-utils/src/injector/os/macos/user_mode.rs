use std::ops::ControlFlow;

use vmi_arch_arm64::{EventMonitor, EventReason, Interrupt, SystemRegister};
use vmi_core::{
    Architecture as _, MemoryAccess, Pa, Registers as _, Va, VcpuId, View, VmiContext, VmiError,
    VmiEventResponse, VmiHandler, VmiSession, VmiState,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryProtection, VmiRead, VmiSetProtection, VmiViewControl,
        VmiVmControl, VmiWrite,
    },
    os::{ProcessId, ThreadObject, VmiOsImageArchitecture, VmiOsProcess as _, VmiOsThread as _},
};
use vmi_os_macos::{ArchAdapter as MacOsArchAdapter, MacOs, MacOsThread};

use super::{
    super::super::{
        BridgeDispatch, InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory,
        Recipe, RecipeExecutor, UserMode,
    },
    Arch,
    kernel_mode::KernelInjectorHandler,
    wake::{WakeRecipeData, wake_recipe},
};

/// Encoding of the `SVC` instruction without its immediate.
const SVC: u32 = 0xd400_0001;

/// Mask of the bits of the `SVC` instruction that do not hold its immediate.
const SVC_MASK: u32 = 0xffe0_001f;

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
/// With a process ID, the injector also wakes a thread of an idle process.
/// At its first event, it arms the first thread of the process that waits to
/// receive a Mach message at a safe point, such as the main thread of an app
/// in its run loop. A kernel-mode injector in the same view then makes the
/// first thread that enters `unix_syscall` call `thread_abort_safely` on the
/// armed thread, which ends its wait.
///
/// # Notes
///
/// The injector restores only the general-purpose registers of the hijacked
/// thread. It hijacks a thread only where a syscall stub returns, because the
/// caller of the stub keeps no value in the caller-saved registers, the SIMD
/// registers among them, which the injected calls may change.
///
/// The receive of a woken thread returns `MACH_RCV_INTERRUPTED`, which the
/// thread sees after the recipe. `mach_msg` receives again, unless its caller
/// passed `MACH_RCV_INTERRUPT`. A process with no thread in such a receive
/// is not woken, and the injector waits for one of its threads to run.
pub struct UserInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiViewControl
        + VmiVmControl,
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

    /// Whether the injector looked for a thread to wake, which it does once.
    wake_started: bool,

    /// Kernel-mode injector that wakes the thread armed at the first event.
    kernel_injector: Option<KernelInjectorHandler<Driver, WakeRecipeData>>,

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
        + VmiQueryProtection
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
            wake_started: false,
            kernel_injector: None,
            recipe: RecipeExecutor::new(recipe),
            state: InjectorState::PreHijack,
            error: None,
        })
    }

    /// Fails with [`VmiError::NotSupported`], because the macOS injector
    /// does not dispatch bridge calls.
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
        + VmiQueryProtection
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
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
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
            // An instruction fetch faults on the page of the armed thread. A
            // read or a write faults on a page that the kernel-mode injector
            // monitors.
            EventReason::MemoryAccess(memory_access) => {
                if memory_access.access.contains(MemoryAccess::X) {
                    self.on_memory_access(vmi)
                }
                else {
                    Ok(self.on_monitored_access(vmi))
                }
            }
            EventReason::WriteSystemRegister(_) => {
                self.start_wake(vmi);

                if let Err(err) = self.on_write_system_register(vmi) {
                    tracing::trace!(%err, "thread not armed");
                }

                Ok(VmiEventResponse::default())
            }
            EventReason::Singlestep(_) => Ok(self.on_singlestep(vmi)),
            EventReason::Interrupt(_) => Ok(self.on_interrupt(vmi)),
        }
    }

    /// Arms a thread of the target process that waits to receive a Mach
    /// message, and starts the kernel-mode injector that wakes it.
    ///
    /// The injector looks once, at its first event before the hijack, and
    /// only with a process ID. When it finds no such thread, or cannot start
    /// the kernel-mode injector, it waits for a thread of the target to run.
    fn start_wake(&mut self, vmi: &VmiContext<MacOs<Driver>>) {
        if self.wake_started || !matches!(self.state, InjectorState::PreHijack) {
            return;
        }

        self.wake_started = true;

        let pid = match self.pid {
            Some(pid) => pid,
            None => return,
        };

        if let Err(err) = self.arm_and_wake(vmi, pid) {
            tracing::warn!(%err, "cannot wake a thread, waiting for one to run");
        }
    }

    /// Arms the first thread of the process that `pid` identifies that waits
    /// to receive a Mach message at a safe point and resumes right after an
    /// `SVC` instruction, and starts the kernel-mode injector that wakes it.
    fn arm_and_wake(
        &mut self,
        vmi: &VmiState<MacOs<Driver>>,
        pid: ProcessId,
    ) -> Result<(), VmiError> {
        let process = match vmi.os().find_process(pid)? {
            Some(process) => process,
            None => return Err(VmiError::Other("target process not found")),
        };
        let root = process.translation_root()?;

        for thread in process.threads()? {
            let thread = thread?;

            // The receive of a Mach message returns to user mode when its
            // wait ends. A BSD syscall can wait again, as `sigsuspend` does.
            if !thread.at_safe_point()? || !thread.waits_for_message()? {
                continue;
            }

            // A thread whose code cannot be read is not woken.
            let ip_va = match Self::resume_address(vmi, &thread, root) {
                Ok(Some(ip_va)) => ip_va,
                Ok(None) => continue,
                Err(err) => {
                    tracing::trace!(%err, "thread skipped");
                    continue;
                }
            };

            let thread_object = thread.object()?;
            let wake = WakeRecipeData::new(vmi, pid, thread.thread_id()?)?;

            self.arm(vmi, pid, thread_object, ip_va, root)?;
            self.kernel_injector = Some(KernelInjectorHandler::in_view(
                vmi,
                self.view,
                wake_recipe(wake),
                thread_object,
            )?);

            tracing::debug!(%pid, thread = %thread_object, %ip_va, "waking thread");
            return Ok(());
        }

        tracing::debug!(%pid, "no thread waits to receive a Mach message");
        Ok(())
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

        let root = current_process.translation_root()?;
        let ip_va = match Self::resume_address(vmi, &current_thread, root)? {
            Some(ip_va) => ip_va,
            None => return Ok(()),
        };

        let current_thread_object = current_thread.object()?;
        if self.thread == Some(current_thread_object) && self.ip_va == Some(ip_va) {
            return Ok(());
        }

        self.arm(vmi, current_pid, current_thread_object, ip_va, root)
    }

    /// Returns the address where a thread resumes in user mode, when the
    /// instruction before it is an `SVC`.
    ///
    /// `root` is the translation root of the process of the thread.
    fn resume_address(
        vmi: &VmiState<MacOs<Driver>>,
        thread: &MacOsThread<'_, Driver>,
        root: Pa,
    ) -> Result<Option<Va>, VmiError> {
        let saved_state = match thread.user_saved_state()? {
            Some(saved_state) => saved_state,
            None => return Ok(None),
        };

        let ip_va = saved_state.instruction_pointer()?;
        if ip_va.is_null() || <Arch as MacOsArchAdapter<Driver>>::is_kernel_address(ip_va) {
            return Ok(None);
        }

        //
        // The thread must resume where a syscall returns. The caller-saved
        // registers hold nothing there that the injected calls could destroy.
        //

        let instruction = vmi.read_u32_in((ip_va - Arch::INSTRUCTION_SIZE, root))?;
        if instruction & SVC_MASK != SVC {
            return Ok(None);
        }

        Ok(Some(ip_va))
    }

    /// Arms a thread of the process that `pid` identifies.
    ///
    /// The thread resumes at `ip_va`, which translates through `root`. An
    /// armed thread replaces the one armed before.
    fn arm(
        &mut self,
        vmi: &VmiState<MacOs<Driver>>,
        pid: ProcessId,
        thread: ThreadObject,
        ip_va: Va,
        root: Pa,
    ) -> Result<(), VmiError> {
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

        tracing::trace!(%pid, %thread, %ip_va, %ip_pa, "thread armed");

        self.pid = Some(pid);
        self.thread = Some(thread);
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

            // The thread runs already. A kernel-mode injector that still
            // waits for a thread has nothing left to do.
            if let Some(kernel_injector) = &mut self.kernel_injector
                && let Err(err) = kernel_injector.cancel(vmi)
            {
                tracing::error!(%err, "failed to cancel the kernel-mode injector");
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

    /// Handles a read or a write of a page that the kernel-mode injector
    /// monitors.
    fn on_monitored_access(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        match &mut self.kernel_injector {
            Some(kernel_injector) => kernel_injector.handle(vmi),
            None => VmiEventResponse::fast_singlestep(vmi.default_view()),
        }
    }

    /// Handles a breakpoint event.
    ///
    /// The kernel-mode injector handles the events of its breakpoint.
    /// Without it, a `BRK` belongs to the guest and goes back to the guest.
    fn on_interrupt(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        match &mut self.kernel_injector {
            Some(kernel_injector) => kernel_injector.handle(vmi),
            None => VmiEventResponse::reinject_interrupt(),
        }
    }

    /// Handles a single-step event.
    ///
    /// Once the vCPU that completed the recipe has single-stepped the
    /// original instruction, every vCPU switches to the default view and the
    /// view is destroyed. A busy kernel-mode injector keeps the view until
    /// `cleanup`. The kernel-mode injector handles every other single-step
    /// event.
    #[tracing::instrument(name = "singlestep", skip_all)]
    fn on_singlestep(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        if !matches!(self.state, InjectorState::Teardown(vcpu) if vcpu == vmi.event().vcpu_id()) {
            return match &mut self.kernel_injector {
                Some(kernel_injector) => kernel_injector.handle(vmi),
                None => VmiEventResponse::default(),
            };
        }

        self.state = InjectorState::Complete;

        // A hijacked kernel thread still returns to the breakpoint in the
        // view. `poll` waits for the kernel-mode injector to finish.
        if self.kernel_injector_is_busy() {
            return VmiEventResponse::default().with_view(self.view);
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

        VmiEventResponse::default()
    }

    /// Returns whether the kernel-mode injector runs its recipe on a hijacked
    /// thread. The view must stay while it does.
    fn kernel_injector_is_busy(&self) -> bool {
        self.kernel_injector
            .as_ref()
            .is_some_and(KernelInjectorHandler::is_busy)
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
        + VmiWrite
        + VmiQueryProtection
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
        // A hijacked kernel thread must get its original registers back
        // before the view goes.
        let kernel_flow = if self.kernel_injector_is_busy() {
            ControlFlow::Continue(())
        }
        else {
            ControlFlow::Break(())
        };

        let flow = match self.state {
            InjectorState::Complete | InjectorState::Failed => return kernel_flow,

            // The guest is still unchanged, apart from a kernel-mode injector
            // that can run.
            InjectorState::PreHijack => {
                self.state = InjectorState::Failed;
                kernel_flow
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

        // The kernel-mode injector removes its breakpoint from the view
        // before the view is destroyed.
        if let Some(kernel_injector) = &mut self.kernel_injector {
            kernel_injector.cleanup(vmi);
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
        // A hijacked kernel thread must get its original registers back
        // before the view goes.
        if self.kernel_injector_is_busy() {
            return None;
        }

        match self.state {
            InjectorState::Complete | InjectorState::Failed => match self.error.take() {
                Some(err) => Some(Err(err)),
                None => Some(Ok(())),
            },
            _ => None,
        }
    }
}
