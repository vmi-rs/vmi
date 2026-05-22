//! Symbol-driven VMI event loop.
//!
//! A [`Reactor`] couples a [`BreakpointManager`] and a
//! [`PageTableMonitor`] so that breakpoints installed at named kernel
//! and module symbols survive page-in / page-out, and so that
//! PatchGuard reads of the kernel image are served from the original,
//! breakpoint-free page.
//!
//! The handler describes its monitored surface through two enums:
//! a module enum produced by [`define_modules!`] and an event enum
//! produced by [`define_events!`]. The event enum lists each symbol
//! to monitor, tagging it with the module that owns it.
//!
//! When `define_modules!` is given a `#[resolver] struct ...;` marker,
//! it also emits a resolver that produces a collection of [`ResolvedEvent`]s.
//! [`Reactor::new`] then installs breakpoints for them.
//!
//! Hits arrive at [`ReactorHandler::handle_event`] as the event enum value.
//!
//! If `handle_event` tries to read a paged-out memory and returns
//! [`VmiError::Translation`], the reactor will inject a page fault
//! to the guest and wait for the next event (which should be the retry
//! of the instruction that caused the page fault).
//!
//! [`BreakpointManager`]: crate::bpm::BreakpointManager
//! [`PageTableMonitor`]: crate::ptm::PageTableMonitor

mod event;
#[doc(hidden)]
pub mod macros;
mod module;
mod profile;

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use vmi_arch_amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt};
use vmi_core::{
    Architecture, MemoryAccess, View, VmiContext, VmiError, VmiEventResponse, VmiHandler, VmiOs,
    VmiSession, driver::VmiFullDriver, os::VmiOsProcess as _,
};
use vmi_os_windows::WindowsOs;

pub use self::{
    event::{EventMetadata, ReactorEvent, ResolvedEvent},
    module::{ModuleMetadata, ModuleMode, ModuleProcessFilter, ReactorModule, ResolvedModule},
    profile::ProfileRef,
};
use super::{
    bpm::{Breakpoint, BreakpointController, BreakpointManager},
    ptm::{self, PageTableMonitor},
};
#[doc(inline)]
pub use crate::{
    _private_define_events as define_events, _private_define_modules as define_modules,
};

/// Action returned by [`ReactorHandler::handle_event`] that determines how
/// the reactor should respond to the event.
#[derive(Default)]
pub enum Action<Arch, T = ()>
where
    Arch: Architecture,
{
    /// Take the default action for the event.
    ///
    /// This means fast-singlestepping over the breakpoint instruction in
    /// the default view (which contains no breakpoint).
    #[default]
    Default,

    /// Respond to the event with a custom VMI response.
    Response(VmiEventResponse<Arch>),

    /// Produce an output, take the default action and then terminate
    /// the reactor.
    Done(T),
}

/// Handles events delivered by the [`Reactor`].
pub trait ReactorHandler<Os>
where
    Os: VmiOs,
{
    /// Value produced by the handler when [`handle_event`] returns
    /// [`Action::Done`].
    ///
    /// [`handle_event`]: Self::handle_event
    type Output;

    /// Event enum that the reactor delivers to [`handle_event`].
    ///
    /// [`handle_event`]: Self::handle_event
    type Event: ReactorEvent;

    /// Handles an event and returns an [`Action`] for the reactor.
    fn handle_event(
        &mut self,
        vmi: &VmiContext<Os>,
        event: Self::Event,
    ) -> Result<Action<Os::Architecture, Self::Output>, VmiError>;
}

/// VMI event loop that delivers breakpoint hits at handler-declared symbols
/// to a [`ReactorHandler`].
pub struct Reactor<Os, Handler>
where
    Os: VmiOs + 'static,
    Os::Driver: VmiFullDriver,
    Os::Architecture: ptm::ArchAdapter<Os::Driver, Handler::Event>,
    Handler: ReactorHandler<Os>,
    <Handler::Event as ReactorEvent>::Module: ReactorModule<Os>,
{
    /// Breakpoint manager that maintains our breakpoints.
    bpm: BreakpointManager<BreakpointController<Os::Driver>, (), Handler::Event>,

    /// Page table monitor that monitors the pages containing our breakpoints.
    ptm: PageTableMonitor<Os::Driver, Handler::Event>,

    /// View where we install our breakpoints and monitor page tables.
    view: View,

    /// Handler that processes our events.
    handler: Handler,

    /// Output produced by the handler.
    output: RefCell<Option<Handler::Output>>,

    /// Optional flag that terminates the event loop once it becomes `true`.
    termination_flag: Option<Arc<AtomicBool>>,
}

impl<Driver, Handler> Reactor<WindowsOs<Driver>, Handler>
where
    Driver: VmiFullDriver<Architecture = Amd64>, // TODO: relax this to any architecture
    Driver::Architecture:
        vmi_os_windows::ArchAdapter<Driver> + ptm::ArchAdapter<Driver, Handler::Event>,
    Handler: ReactorHandler<WindowsOs<Driver>>,
    <Handler::Event as ReactorEvent>::Module: ReactorModule<WindowsOs<Driver>>,
{
    /// Creates a reactor and installs one breakpoint per resolved event.
    ///
    /// Pauses the guest, enables the breakpoint and singlestep monitors,
    /// creates a fresh RWX view, switches every vCPU onto it, and inserts
    /// one [`Breakpoint`] plus one [`PageTableMonitor`] entry per event.
    /// The breakpoint context `(va, root)` uses the system process root
    /// for kernel-owned events and the owning process root for user-mode
    /// events, so the same EPT entry covers every process that maps the
    /// underlying physical page.
    pub fn new(
        session: &VmiSession<WindowsOs<Driver>>,
        handler: Handler,
        events: impl AsRef<[ResolvedEvent<Handler::Event>]>,
    ) -> Result<Self, VmiError> {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        // Enable the necessary monitors.
        vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        // Create a fresh RWX view and switch all vCPUs onto it.
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        // Install breakpoints and page table monitors for the resolved symbols.
        let system_process = vmi.os().system_process()?;
        let system_root = system_process.translation_root()?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();

        for event in events.as_ref() {
            let root = match event.process {
                Some(process) => vmi.os().process(process)?.translation_root()?,
                None => system_root,
            };
            let cx = (event.address, root);
            let bp = Breakpoint::new(cx, view).global().with_tag(event.event);

            bpm.insert(&vmi, bp)?;
            ptm.monitor(&vmi, cx, view, event.event)?;
        }

        Ok(Self {
            bpm,
            ptm,
            view,
            handler,
            output: RefCell::new(None),
            termination_flag: None,
        })
    }

    /// Installs a flag that terminates the event loop once it becomes `true`.
    pub fn with_termination_flag(self, termination_flag: Arc<AtomicBool>) -> Self {
        Self {
            termination_flag: Some(termination_flag),
            ..self
        }
    }

    /// Handles a memory access event on a watched page.
    ///
    /// On a write access, marks the touched page-table entry as dirty
    /// so the singlestep callback can re-evaluate the mapping, and
    /// redirects the instruction to the default view (which carries no
    /// breakpoints) so the write actually lands.
    ///
    /// On a read access, redirects the instruction to the default view
    /// so a PatchGuard sees the unmodified kernel.
    #[tracing::instrument(
        skip_all,
        fields(
            pa = %vmi.event().reason().as_memory_access().pa,
            va = %vmi.event().reason().as_memory_access().va,
            access = %vmi.event().reason().as_memory_access().access,
        )
    )]
    fn memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Driver::Architecture>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        // Since Intel CPUs set both the `R` and `W` flags for write accesses,
        // we check `W` first.
        if memory_access.access.contains(MemoryAccess::W) {
            // Typically the OS modifying a page-table entry that maps one of
            // our "breakpointed" pages. Mark the entry as dirty so the
            // singlestep callback can examine the new PTE and detect
            // page-in / page-out.
            //
            // The writing instruction must execute against the default view,
            // where the entry is not write-protected, so the write can land.
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());

            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            // Typically PatchGuard verifying that kernel pages have not been
            // tampered with.
            //
            // The reading instruction must execute against the `default_view`
            // (which carries no breakpoint bytes), so PatchGuard sees the
            // unmodified kernel and is satisfied.
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("unhandled memory access: {memory_access:?}");
        }
    }

    /// Handles a software breakpoint interrupt.
    ///
    /// Looks up the event tag in [`BreakpointManager`], delivers it to
    /// [`ReactorHandler::handle_event`], and applies the returned
    /// [`Action`].
    ///
    /// Unknown breakpoints are reinjected so the guest can handle them.
    /// Stale breakpoint events (e.g. when we removed a breakpoint, but
    /// the breakpoint event was already queued) are stepped over against
    /// the default view.
    #[tracing::instrument(skip_all)]
    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Driver::Architecture>, VmiError> {
        let tag = match self.bpm.get_by_event(vmi.event(), ()) {
            Some(mut breakpoints) => {
                assert!(
                    breakpoints.len() == 1,
                    "multiple breakpoints for the same event"
                );

                breakpoints.next().expect("breakpoint").tag()
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    tracing::debug!("unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }

                tracing::debug!("ignoring old breakpoint event");
                return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
            }
        };

        if self.output.borrow().is_some() {
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        match self.handler.handle_event(vmi, tag)? {
            Action::Default => (),
            Action::Response(response) => return Ok(response),
            Action::Done(output) => {
                self.output.borrow_mut().replace(output);
            }
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    /// Handles a singlestep that follows after a memory write to
    /// a monitored PTE.
    ///
    /// Drains the dirty PTE list collected in [`memory_access`], lets the
    /// breakpoint manager react to page-in / page-out events, then resumes
    /// guest execution back on the reactor's view.
    ///
    /// [`memory_access`]: Self::memory_access
    #[tracing::instrument(skip_all)]
    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Driver::Architecture>, VmiError> {
        // Get the page table modifications by processing the dirty page table
        // entries.
        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;

        // Let the breakpoint controller handle the page table modifications.
        self.bpm.handle_ptm_events(vmi, ptm_events)?;

        // Disable singlestep and switch back to our view.
        Ok(VmiEventResponse::default().with_view(self.view))
    }

    /// Dispatches a VMI event to the matching handler.
    ///
    /// Routes VMI event reasons to their per-event handlers, and turns
    /// a translation failure into an injected page fault so the guest can
    /// page the address in and retry the faulting instruction.
    #[tracing::instrument(
        name = "reactor",
        skip_all,
        fields(
            vcpu = %vmi.event().vcpu_id(),
            view = vmi_core::trace::event_view(vmi.event()),

            pid = vmi_core::trace::current_process_id(vmi),
            tid = vmi_core::trace::current_thread_id(vmi),
            //name = vmi_core::trace::current_process_name(vmi),
        )
    )]
    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Driver::Architecture>, VmiError> {
        let event = vmi.event();
        let result = match event.reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            EventReason::Singlestep(_) => self.singlestep(vmi),
            _ => panic!("unhandled event: {:?}", event.reason()),
        };

        // If VMI tries to read from a page that is not present, it will return
        // a page fault error. In this case, we inject a page fault interrupt
        // to the guest.
        //
        // Once the guest handles the page fault, it will try to retry the
        // instruction that caused the page fault.
        if let Err(VmiError::Translation(pfs)) = result {
            tracing::debug!(va = %pfs[0].va, "page fault");
            vmi.inject_interrupt(event.vcpu_id(), Interrupt::page_fault(pfs[0].va, 0))?;
            return Ok(VmiEventResponse::default());
        }

        result
    }
}

impl<Driver, Handler> VmiHandler<WindowsOs<Driver>> for Reactor<WindowsOs<Driver>, Handler>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
    Handler: ReactorHandler<WindowsOs<Driver>>,
    <Handler::Event as ReactorEvent>::Module: ReactorModule<WindowsOs<Driver>>,
{
    type Output = Option<Handler::Output>;

    fn handle_event(
        &mut self,
        vmi: VmiContext<WindowsOs<Driver>>,
    ) -> VmiEventResponse<Driver::Architecture> {
        // Flush the V2P cache on every event to avoid stale translations.
        vmi.flush_v2p_cache();

        self.dispatch(&vmi).expect("dispatch")
    }

    fn cleanup(&mut self, vmi: &VmiSession<WindowsOs<Driver>>) {
        if let Err(err) = vmi.switch_to_view(vmi.default_view()) {
            tracing::error!(%err, "failed to switch to default view");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Singlestep) {
            tracing::error!(%err, "failed to disable singlestep");
        }

        if let Err(err) = vmi.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))
        {
            tracing::error!(%err, "failed to disable breakpoint interrupt");
        }

        match self.bpm.remove_by_view(vmi, self.view) {
            Ok(true) => {}
            Ok(false) => tracing::warn!("no breakpoints to remove"),
            Err(err) => tracing::error!(%err, "failed to remove breakpoints"),
        }

        self.ptm.unmonitor_all(vmi);

        if let Err(err) = vmi.destroy_view(self.view) {
            tracing::error!(%err, "failed to destroy view");
        }
    }

    fn poll(&self) -> Option<Self::Output> {
        if let Some(terminate_flag) = &self.termination_flag
            && terminate_flag.load(Ordering::Relaxed)
        {
            Some(None)
        }
        else {
            self.output.borrow_mut().take().map(Some)
        }
    }
}
