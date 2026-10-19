use std::ops::ControlFlow;

use vmi_arch_arm64::{EventMonitor, EventReason};
use vmi_core::{
    AddressContext, MemoryAccess, Registers as _, Va, VcpuId, View, VmiContext, VmiCore, VmiError,
    VmiEventResponse, VmiHandler, VmiSession, VmiState,
    driver::{
        VmiDriver, VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead,
        VmiSetProtection, VmiViewControl, VmiVmControl, VmiWrite,
    },
    os::{ProcessId, ThreadObject, VmiOsProcess as _, VmiOsThread as _},
};
use vmi_os_macos::{MacOs, MacOsExt as _};

use super::{
    super::super::{
        BridgeDispatch, InjectorExecutionAdapter, InjectorHandlerAdapter, InjectorHandlerFactory,
        KernelMode, Recipe, RecipeExecutor,
    },
    Arch,
};
use crate::{
    bpm::{Breakpoint, BreakpointController, BreakpointManager},
    ptm::PageTableMonitor,
};

/// Tag of the breakpoint at the entry of `unix_syscall`.
const UNIX_SYSCALL: &str = "unix_syscall";

/// Lifecycle state of the kernel-mode injector.
enum InjectorState {
    /// Waiting for a thread to enter `unix_syscall`.
    PreHijack,

    /// Thread hijacked, executing the injection recipe.
    Executing,

    /// Recipe finished or aborted, single-stepping the original instruction
    /// of the hijacked thread before the breakpoint is removed.
    ///
    /// The [`VcpuId`] identifies the vCPU that completed the recipe. Only a
    /// single-step event from this vCPU shows that the thread is past the
    /// breakpoint.
    Teardown(VcpuId),

    /// Injection complete, the result is available.
    Complete,

    /// Injection failed before the hijack, the error is available.
    Failed,
}

/// Kernel-mode injector for macOS on Apple silicon.
///
/// Every BSD syscall from user mode enters `unix_syscall`, with interrupts
/// enabled and no lock held. A `BRK` at its entry, in the view of the
/// injector, stops the first thread that arrives, and that thread runs the
/// recipe. Each injected call returns to the entry and hits the `BRK` again,
/// which runs the next step. At the end, the thread gets its registers back
/// and single-steps the original instruction in the default view, and the
/// injector removes the `BRK`.
///
/// The user-mode injector runs one in its own view to wake a thread of an
/// idle process.
///
/// # Notes
///
/// The injected calls may block, and the hijacked thread can then go on on
/// another vCPU. The injector therefore follows the thread by its thread
/// object, not by its vCPU.
pub struct KernelInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiViewControl
        + VmiVmControl,
{
    /// Process ID whose thread runs the recipe, or `None` for any process.
    pid: Option<ProcessId>,

    /// Thread that must not run the recipe, because the recipe acts on it.
    excluded: Option<ThreadObject>,

    /// Thread that runs the recipe, once a thread hits the breakpoint.
    thread: Option<ThreadObject>,

    /// Memory view that holds the breakpoint.
    view: View,

    /// Whether the injector created the view.
    ///
    /// The injector destroys a view of its own at the end. The view of the
    /// user-mode injector stays, because that injector still uses it.
    owns_view: bool,

    /// Whether the view is destroyed.
    ///
    /// A vCPU can hold the view for a moment after the switch to the default
    /// view, and `cleanup` then destroys it.
    view_destroyed: bool,

    /// Whether the breakpoint, the monitoring of its translation and the
    /// breakpoint monitor are in place.
    installed: bool,

    /// Breakpoint manager for the breakpoint at the entry of `unix_syscall`.
    bpm: BreakpointManager<BreakpointController<Driver>>,

    /// Page table monitor for the translation of the entry of
    /// `unix_syscall`.
    ptm: PageTableMonitor<Driver>,

    /// Executor for running the injection recipe.
    recipe: RecipeExecutor<MacOs<Driver>, T>,

    /// Current lifecycle state of the injector.
    state: InjectorState,

    /// Error that ended the injection.
    error: Option<VmiError>,
}

impl<Driver, T> InjectorHandlerFactory<MacOs<Driver>, KernelMode, T>
    for KernelInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
        + VmiEventControl
        + VmiViewControl
        + VmiVmControl,
{
    fn new(
        vmi: &VmiSession<MacOs<Driver>>,
        recipe: Recipe<MacOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        // The registers of a paused vCPU give the translation root of the
        // kernel.
        let paused = vmi.pause_guard()?;
        let ctx = unix_syscall_context(&paused.state())?;
        drop(paused);

        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        vmi.monitor_enable(EventMonitor::Singlestep)?;

        let mut injector = Self::create(view, true, recipe);
        if let Err(err) = injector.install(vmi, ctx) {
            injector.cleanup(vmi);
            return Err(err);
        }

        Ok(injector)
    }

    /// Fails with [`VmiError::NotSupported`], because macOS has no bridge.
    fn with_bridge<Bridge>(
        self,
        _bridge: Bridge,
    ) -> Result<<MacOs<Driver> as InjectorExecutionAdapter<KernelMode, T, Bridge>>::Handler, VmiError>
    where
        Bridge: BridgeDispatch<MacOs<Driver>>,
        MacOs<Driver>: InjectorExecutionAdapter<KernelMode, T, Bridge>,
    {
        Err(VmiError::NotSupported)
    }
}

impl<Driver, T> InjectorHandlerAdapter<MacOs<Driver>, KernelMode, T, ()>
    for KernelInjectorHandler<Driver, T>
where
    Driver: VmiDriver<Architecture = Arch>
        + VmiRead
        + VmiWrite
        + VmiQueryProtection
        + VmiSetProtection
        + VmiQueryRegisters
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

impl<Driver, T> KernelInjectorHandler<Driver, T>
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
    /// Creates an injector whose breakpoint lives in `view`, the view of the
    /// user-mode injector, and that never hijacks the thread `excluded`.
    ///
    /// The user-mode injector keeps the view and the single-step monitor.
    pub(super) fn in_view(
        vmi: &VmiState<MacOs<Driver>>,
        view: View,
        recipe: Recipe<MacOs<Driver>, T>,
        excluded: ThreadObject,
    ) -> Result<Self, VmiError> {
        let ctx = unix_syscall_context(vmi)?;

        let mut injector = Self::create(view, false, recipe);
        injector.excluded = Some(excluded);

        if let Err(err) = injector.install(vmi, ctx) {
            injector.cleanup(vmi);
            return Err(err);
        }

        Ok(injector)
    }

    /// Creates an injector in `view` before its breakpoint is installed.
    fn create(view: View, owns_view: bool, recipe: Recipe<MacOs<Driver>, T>) -> Self {
        Self {
            pid: None,
            excluded: None,
            thread: None,
            view,
            owns_view,
            view_destroyed: false,
            installed: false,
            bpm: BreakpointManager::new(),
            ptm: PageTableMonitor::new(),
            recipe: RecipeExecutor::new(recipe),
            state: InjectorState::PreHijack,
            error: None,
        }
    }

    /// Installs the breakpoint at `ctx` and the monitoring of its
    /// translation.
    ///
    /// The view is active already, and a `BRK` that a vCPU hits before its
    /// trap is in place goes to the guest kernel, which panics. The VM
    /// therefore stays paused until the monitor and the breakpoint are both
    /// in place, and every vCPU applies the monitor before it runs again.
    fn install(&mut self, vmi: &VmiCore<Driver>, ctx: AddressContext) -> Result<(), VmiError> {
        let _pause_guard = vmi.pause_guard()?;

        vmi.monitor_enable(EventMonitor::Breakpoint)?;
        self.installed = true;

        self.ptm.monitor(vmi, ctx, self.view, UNIX_SYSCALL)?;

        let breakpoint = Breakpoint::new(ctx, self.view)
            .global()
            .with_tag(UNIX_SYSCALL);
        self.bpm.insert(vmi, breakpoint)?;

        Ok(())
    }

    /// Returns whether a hijacked thread runs the recipe or has not got its
    /// original registers back yet.
    ///
    /// The view must stay in place until the injector is no longer busy. A
    /// hijacked thread that returns to an entry without the breakpoint runs
    /// `unix_syscall` with the registers of an injected call.
    pub(super) fn is_busy(&self) -> bool {
        matches!(
            self.state,
            InjectorState::Executing | InjectorState::Teardown(_)
        )
    }

    /// Removes the breakpoint if no thread has hit it yet.
    pub(super) fn cancel(&mut self, vmi: &VmiCore<Driver>) -> Result<(), VmiError> {
        if !matches!(self.state, InjectorState::PreHijack) {
            return Ok(());
        }

        self.state = InjectorState::Complete;
        self.remove(vmi)
    }

    /// Handles an event of the injector.
    ///
    /// The user-mode injector passes on the events of the injector that runs
    /// in its view.
    pub(super) fn handle(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        match self.dispatch(vmi) {
            Ok(response) => response,
            Err(err) => self.on_error(vmi, err),
        }
    }

    #[tracing::instrument(
        name = "kernel_injector",
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
            EventReason::MemoryAccess(_) => Ok(self.on_memory_access(vmi)),
            EventReason::Interrupt(_) => self.on_interrupt(vmi),
            EventReason::Singlestep(_) => self.on_singlestep(vmi),

            // The injector monitors no system register.
            EventReason::WriteSystemRegister(_) => Ok(VmiEventResponse::default()),
        }
    }

    /// Handles a breakpoint event.
    ///
    /// The first thread that hits the breakpoint runs the recipe, and every
    /// other thread passes it. A `BRK` of the guest goes back to the guest.
    #[tracing::instrument(name = "breakpoint", skip_all)]
    fn on_interrupt(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
        let interrupt = match vmi.event().reason() {
            EventReason::Interrupt(interrupt) => interrupt,
            _ => return Ok(VmiEventResponse::default()),
        };

        // The breakpoints of vmi are `BRK #0`. Any other exception belongs
        // to the guest, such as the `BRK` that panics the kernel after a
        // failed pointer authentication.
        if interrupt.interrupt.breakpoint_comment() != Some(0) {
            return Ok(VmiEventResponse::reinject_interrupt());
        }

        if self.bpm.get_by_event(vmi.event(), ()).is_none() {
            // A `BRK #0` that is still in memory belongs to the guest.
            // Otherwise the injector removed its breakpoint after the vCPU
            // hit it.
            if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                return Ok(VmiEventResponse::reinject_interrupt());
            }

            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Early exit if the recipe is no longer executing. A vCPU can still
        // report the breakpoint after the recipe ends.
        //

        if !matches!(
            self.state,
            InjectorState::PreHijack | InjectorState::Executing
        ) {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        //
        // Take the first thread that enters `unix_syscall`, and follow it
        // afterwards. Every other thread passes the breakpoint.
        //

        let current_thread = vmi.os().current_thread()?;
        let current_thread_object = current_thread.object()?;

        match self.thread {
            Some(thread) => {
                if thread != current_thread_object {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }
            }
            None => {
                if Some(current_thread_object) == self.excluded {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }

                // An exiting thread whose process is already detached does
                // not run the recipe.
                let current_process = match current_thread.attached_process()? {
                    Some(current_process) => current_process,
                    None => return Ok(VmiEventResponse::fast_singlestep(vmi.default_view())),
                };

                let current_pid = current_process.id()?;
                if let Some(pid) = self.pid
                    && current_pid != pid
                {
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }

                tracing::debug!(
                    %current_pid,
                    thread = %current_thread_object,
                    name = current_process.name().as_deref().unwrap_or("<unknown>"),
                    "kernel thread hijacked"
                );

                self.thread = Some(current_thread_object);
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
                Ok(new_registers) => new_registers,
                Err(err) => {
                    tracing::error!(%err, "kernel recipe failed");
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
        // follows shows that the thread is past the breakpoint, and the
        // breakpoint is removed there.
        //

        self.state = InjectorState::Teardown(vmi.event().vcpu_id());

        Ok(VmiEventResponse::singlestep()
            .with_registers(new_registers.gp_registers())
            .with_view(vmi.default_view()))
    }

    /// Handles a read or a write of a page that the injector monitors.
    ///
    /// A write to a page table is single-stepped in the default view, and
    /// [`on_singlestep`](Self::on_singlestep) then processes it. A read of
    /// the page of the breakpoint reads the original bytes in the default
    /// view.
    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        let memory_access = match vmi.event().reason() {
            EventReason::MemoryAccess(memory_access) => memory_access,
            _ => return VmiEventResponse::default(),
        };

        if memory_access.access.contains(MemoryAccess::W) {
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());

            return VmiEventResponse::singlestep().with_view(vmi.default_view());
        }

        VmiEventResponse::fast_singlestep(vmi.default_view())
    }

    /// Handles a single-step event.
    ///
    /// Removes the breakpoint once the hijacked thread is past it, and
    /// otherwise processes the page table writes of the vCPU. The vCPU then
    /// returns to the view of the injector, unless the injector is done with
    /// a view of its own.
    #[tracing::instrument(name = "singlestep", skip_all)]
    fn on_singlestep(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
        if let InjectorState::Teardown(vcpu) = self.state
            && vcpu == vmi.event().vcpu_id()
        {
            self.state = InjectorState::Complete;
            self.remove(vmi)?;

            // The view of the user-mode injector stays in use.
            if !self.owns_view {
                return Ok(VmiEventResponse::default().with_view(self.view));
            }

            // Single-step monitoring stays enabled until `cleanup`. The
            // response without the single-step action stops stepping this
            // vCPU.
            vmi.switch_to_view(vmi.default_view())?;

            match vmi.destroy_view(self.view) {
                Ok(()) => self.view_destroyed = true,
                Err(err) => tracing::debug!(%err, "view still in use, destroying it at cleanup"),
            }

            return Ok(VmiEventResponse::default());
        }

        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, ptm_events)?;

        Ok(VmiEventResponse::default().with_view(self.view))
    }

    /// Records `err` as the error that ends the injection.
    ///
    /// Before the hijack, the injection ends at once and the breakpoint is
    /// removed. While the recipe is executing, it ends once the hijacked
    /// thread has its original registers back.
    fn on_error(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        err: VmiError,
    ) -> VmiEventResponse<Arch> {
        tracing::error!(%err, "kernel injection failed");

        if self.error.is_none() {
            self.error = Some(err);
        }

        if matches!(self.state, InjectorState::PreHijack) {
            self.state = InjectorState::Failed;

            if let Err(err) = self.remove(vmi) {
                tracing::error!(%err, "failed to remove the kernel breakpoint");
            }
        }

        // A single-step runs in the default view. The vCPU returns to the
        // view of the injector, which still holds the breakpoint for a
        // hijacked thread, or the trap of the user-mode injector.
        match vmi.event().reason() {
            EventReason::Singlestep(_) if !self.view_destroyed => {
                VmiEventResponse::default().with_view(self.view)
            }
            _ => VmiEventResponse::default(),
        }
    }

    /// Removes the breakpoint, the monitoring of its translation and the
    /// breakpoint monitor, with the VM paused.
    ///
    /// The breakpoint goes before the monitor. A vCPU that hit it without
    /// the monitor would pass the `BRK` to the guest kernel.
    fn remove(&mut self, vmi: &VmiCore<Driver>) -> Result<(), VmiError> {
        if !self.installed {
            return Ok(());
        }

        let _pause_guard = vmi.pause_guard()?;
        self.installed = false;

        self.bpm.remove_by_view(vmi, self.view)?;
        self.ptm.unmonitor_view(vmi, self.view);
        vmi.monitor_disable(EventMonitor::Breakpoint)
    }
}

impl<Driver, T> VmiHandler<MacOs<Driver>> for KernelInjectorHandler<Driver, T>
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
        self.handle(&vmi)
    }

    fn handle_interrupted(&mut self, _vmi: &VmiSession<MacOs<Driver>>) -> ControlFlow<()> {
        let flow = match self.state {
            InjectorState::Complete | InjectorState::Failed => return ControlFlow::Break(()),

            // The guest is still unchanged, and `cleanup` removes the
            // breakpoint.
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
        if self.is_busy() {
            tracing::error!("kernel injection ends while a hijacked thread runs the recipe");
        }

        if let Err(err) = self.remove(vmi) {
            tracing::error!(%err, "failed to remove the kernel breakpoint");
        }

        // The user-mode injector keeps its view and its single-step monitor.
        if !self.owns_view {
            return;
        }

        if !self.view_destroyed {
            if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
                tracing::error!(%err, "failed to switch to default view");
            }

            if let Err(err) = vmi.destroy_view(self.view) {
                tracing::error!(%err, "failed to destroy view");
            }
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

/// Returns the address context of the entry of `unix_syscall`.
fn unix_syscall_context<Driver>(vmi: &VmiState<MacOs<Driver>>) -> Result<AddressContext, VmiError>
where
    Driver: VmiDriver<Architecture = Arch> + VmiRead,
{
    let entry = match vmi.os().symbols().unix_syscall {
        Some(unix_syscall) => Va(unix_syscall),
        None => return Err(VmiError::Other("unix_syscall not found")),
    };

    Ok(AddressContext::new(
        entry,
        vmi.registers().translation_root(entry),
    ))
}
