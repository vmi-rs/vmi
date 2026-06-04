//! Minimal parallel arm64 VMI reactor.
//!
//! Installs software breakpoints at caller-supplied `(va, root)` contexts in a
//! fresh RWX view, delivers each `BRK` hit to a [`ReactorHandler`], and steps
//! over the original instruction in the default view. This is the arm64
//! counterpart of [`crate::reactor`], kept separate so the amd64 reactor stays
//! untouched. It has no page-table monitor, so it targets resident memory
//! (kernel symbols). Growing it to cover pageable targets is future work.

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use vmi_arch_arm64::{Arm64, EventMonitor, EventReason};
use vmi_core::{
    Architecture as _, MemoryAccess, MemoryAccessOptions, Pa, Va, View, VmiContext, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    arch::{EventMemoryAccess as _, EventReason as _},
    driver::VmiFullDriver,
};
use vmi_os_windows::WindowsOs;

use crate::bpm::{Breakpoint, BreakpointController, BreakpointManager};

/// One breakpoint to install.
#[derive(Debug, Clone, Copy)]
pub struct BreakpointSpec {
    /// Virtual address of the breakpoint.
    pub va: Va,

    /// Translation root that maps `va`. For a kernel symbol on arm64 this is the
    /// `TTBR1_EL1` base, that is, `Registers::translation_root` of a high VA.
    pub root: Pa,

    /// Tag handed back to the handler when this breakpoint is hit.
    pub tag: &'static str,
}

/// Action returned by [`ReactorHandler::handle_breakpoint`].
#[expect(
    clippy::large_enum_variant,
    reason = "Response variant is large by design"
)]
#[derive(Default)]
pub enum Action<T = ()> {
    /// Step over the breakpoint in the default view.
    #[default]
    Default,

    /// Apply a custom response.
    Response(VmiEventResponse<Arm64>),

    /// Produce an output, step over, and terminate the reactor.
    Done(T),
}

/// Handles breakpoint hits delivered by [`ReactorArm64`].
pub trait ReactorHandler<Driver>
where
    Driver: VmiFullDriver<Architecture = Arm64>,
{
    /// Value produced when [`handle_breakpoint`](Self::handle_breakpoint)
    /// returns [`Action::Done`].
    type Output;

    /// Handles a breakpoint hit identified by `tag`.
    fn handle_breakpoint(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        tag: &'static str,
    ) -> Result<Action<Self::Output>, VmiError>;
}

/// Minimal arm64 reactor: breakpoint hit to handler to fast singlestep.
pub struct ReactorArm64<Driver, Handler>
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture: vmi_os_windows::ArchAdapter<Driver>,
    Handler: ReactorHandler<Driver>,
{
    /// Breakpoint manager owning the installed breakpoints.
    bpm: BreakpointManager<BreakpointController<Driver>, (), &'static str>,

    /// View where the breakpoints live.
    view: View,

    /// Handler that processes hits.
    handler: Handler,

    /// Output captured when the handler returns [`Action::Done`].
    output: RefCell<Option<Handler::Output>>,

    /// Flag that terminates the loop once it becomes `true`.
    termination_flag: Option<Arc<AtomicBool>>,
}

impl<Driver, Handler> ReactorArm64<Driver, Handler>
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture: vmi_os_windows::ArchAdapter<Driver>,
    Handler: ReactorHandler<Driver>,
{
    /// Creates a reactor and installs one stealth breakpoint per spec.
    ///
    /// Pauses the guest, enables the breakpoint and singlestep monitors, creates
    /// a fresh RWX view, switches every vCPU onto it, and inserts one breakpoint
    /// per spec. Each spec carries a precomputed `(va, root)` so the caller
    /// selects the regime (`TTBR1` for kernel VAs).
    ///
    /// Each breakpoint page is left execute-only so a PatchGuard read traps and
    /// is served the clean bytes, preserving stealth. On a 16K host the same
    /// stage-2 leaf also covers the neighbor guest pages fused into the host
    /// page, so each breakpoint requests in-kernel auto-step of those neighbors
    /// (`MemoryAccessOptions::AUTO_STEP_NEIGHBORS`): a neighbor data access is
    /// retired in the kernel rather than storming the agent, while reads of the
    /// breakpoint page itself still deliver to [`Self::memory_access`].
    pub fn new(
        session: &VmiSession<WindowsOs<Driver>>,
        handler: Handler,
        breakpoints: &[BreakpointSpec],
    ) -> Result<Self, VmiError> {
        Self::new_impl(session, handler, breakpoints, true)
    }

    /// Creates a reactor with X-only stealth disabled (breakpoint pages stay
    /// RWX).
    ///
    /// The breakpoint manager arms its page as execute-only to trap reads and
    /// hide the planted bytes from PatchGuard. This constructor widens each
    /// breakpoint page back to RWX after insertion, so no read or neighbor
    /// access faults at all. Use it for bring-up where PatchGuard is not a
    /// concern: it cannot storm, but PatchGuard can read the planted bytes.
    /// For a sustained Windows target use [`Self::new`], which keeps the page
    /// execute-only and auto-steps the fused neighbors in the kernel.
    pub fn new_without_stealth(
        session: &VmiSession<WindowsOs<Driver>>,
        handler: Handler,
        breakpoints: &[BreakpointSpec],
    ) -> Result<Self, VmiError> {
        Self::new_impl(session, handler, breakpoints, false)
    }

    /// Builds the reactor, installing one breakpoint per spec.
    ///
    /// When `stealth` is true, each breakpoint page stays execute-only and its
    /// fused neighbor pages are marked for in-kernel auto-step. When false, the
    /// execute-only narrowing is undone per page (widened to RWX) so no data
    /// access faults.
    fn new_impl(
        session: &VmiSession<WindowsOs<Driver>>,
        handler: Handler,
        breakpoints: &[BreakpointSpec],
        stealth: bool,
    ) -> Result<Self, VmiError> {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        vmi.monitor_enable(EventMonitor::Breakpoint)?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        let mut bpm = BreakpointManager::new();
        for spec in breakpoints {
            let cx = (spec.va, spec.root);
            let bp = Breakpoint::new(cx, view).global().with_tag(spec.tag);
            bpm.insert(&vmi, bp)?;

            // The breakpoint manager armed the page execute-only. Re-set its
            // access to pick how the 16K-fusion neighbor pages are handled.
            // With stealth on, request in-kernel auto-step of the neighbors so
            // PatchGuard reads of the breakpoint page still trap to userspace
            // while the fused neighbors are retired in the kernel (no event
            // storm). With stealth off, widen back to RWX (no protection, no
            // events) for storm-free bring-up.
            let pa = vmi.core().translate_address((spec.va, spec.root))?;
            let gfn = Arm64::gfn_from_pa(pa);
            if stealth {
                vmi.core().set_memory_access_with_options(
                    gfn,
                    view,
                    MemoryAccess::X,
                    MemoryAccessOptions::AUTO_STEP_NEIGHBORS,
                )?;
            }
            else {
                vmi.core().set_memory_access(gfn, view, MemoryAccess::RWX)?;
            }
        }

        Ok(Self {
            bpm,
            view,
            handler,
            output: RefCell::new(None),
            termination_flag: None,
        })
    }

    /// Installs a flag that terminates the loop once it becomes `true`.
    pub fn with_termination_flag(self, termination_flag: Arc<AtomicBool>) -> Self {
        Self {
            termination_flag: Some(termination_flag),
            ..self
        }
    }

    /// Handles a software breakpoint hit.
    ///
    /// Looks up the tag in the breakpoint manager and delivers it to the
    /// handler. An unknown but genuine breakpoint is reinjected to the guest; a
    /// stale event is stepped over against the default view.
    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Arm64>, VmiError> {
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

        match self.handler.handle_breakpoint(vmi, tag)? {
            Action::Default => (),
            Action::Response(response) => return Ok(response),
            Action::Done(output) => {
                self.output.borrow_mut().replace(output);
            }
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    /// Handles a memory-access violation on a breakpointed page.
    ///
    /// The breakpoint view marks the shadow page execute-only, so any data
    /// access to it traps here. On a write the OS or PatchGuard is modifying
    /// the page, so the instruction is stepped on the clean default view where
    /// it can land. On a read PatchGuard is verifying the page, so the
    /// instruction is stepped on the clean default view and sees the unpatched
    /// bytes, preserving stealth.
    ///
    /// X-only protection is host-page granular, so on a host whose page size
    /// exceeds the guest granule a data access to a neighbor guest page fused
    /// into the same host page also faults here. Such an access is handled the
    /// same way: stepped over on the default view.
    fn memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Arm64>, VmiError> {
        let ma = vmi
            .event()
            .reason()
            .as_memory_access()
            .expect("memory access");

        // Write accesses may also have R set, so check W first.
        if ma.access().contains(MemoryAccess::W) {
            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if ma.access().contains(MemoryAccess::R) {
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("unhandled memory access: {ma:?}");
        }
    }

    /// Dispatches a VMI event to its handler.
    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Arm64>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            // After a write step-over on the default view, return execution to
            // the breakpoint view so later instructions still trap the BRK.
            EventReason::Singlestep(_) => Ok(VmiEventResponse::default().with_view(self.view)),
        }
    }
}

impl<Driver, Handler> VmiHandler<WindowsOs<Driver>> for ReactorArm64<Driver, Handler>
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture: vmi_os_windows::ArchAdapter<Driver>,
    Handler: ReactorHandler<Driver>,
{
    type Output = Option<Handler::Output>;

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Arm64> {
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

        if let Err(err) = vmi.monitor_disable(EventMonitor::Breakpoint) {
            tracing::error!(%err, "failed to disable breakpoint");
        }

        match self.bpm.remove_by_view(vmi, self.view) {
            Ok(true) => {}
            Ok(false) => tracing::warn!("no breakpoints to remove"),
            Err(err) => tracing::error!(%err, "failed to remove breakpoints"),
        }

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
