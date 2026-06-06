//! Minimal parallel arm64 VMI reactor.
//!
//! Installs software breakpoints at caller-supplied `(va, root)` contexts in a
//! fresh RWX view, delivers each `BRK` hit to a [`ReactorHandler`], and steps
//! over the original instruction in the default view. This is the arm64
//! counterpart of [`crate::reactor`], kept separate so the amd64 reactor stays
//! untouched. It couples the breakpoint manager with a page-table monitor, so a
//! breakpoint at a pageable (user-mode) target is (de)activated as its page
//! pages in and out; a resident kernel target simply never pages.

use std::{
    cell::RefCell,
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use vmi_arch_arm64::{Arm64, EventMonitor, EventReason};
use vmi_core::{
    Architecture as _, Hfn, MemoryAccess, Pa, Va, View, VmiContext, VmiCore, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    arch::{EventMemoryAccess as _, EventReason as _},
    driver::VmiFullDriver,
};
use vmi_os_windows::WindowsOs;

use crate::{
    bpm::{Breakpoint, BreakpointController, BreakpointManager},
    ptm::{PageTableMonitor, PageTableMonitorEvent},
};

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
    Driver::Architecture:
        vmi_os_windows::ArchAdapter<Driver> + crate::ptm::ArchAdapter<Driver, &'static str>,
    Handler: ReactorHandler<Driver>,
{
    /// Breakpoint manager owning the installed breakpoints.
    bpm: BreakpointManager<BreakpointController<Driver>, (), &'static str>,

    /// Page table monitor following each target's page-table path so a pageable
    /// target's breakpoint can be (de)activated on page-in / page-out.
    ptm: PageTableMonitor<Driver, &'static str>,

    /// View where the breakpoints live.
    view: View,

    /// Breakpoint specs, retained so the per-host-frame access mask can be
    /// recomputed when a pageable target pages in.
    breakpoints: Vec<BreakpointSpec>,

    /// Whether breakpoint pages are kept execute-only (stealth) or widened to
    /// RWX.
    stealth: bool,

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
    Driver::Architecture:
        vmi_os_windows::ArchAdapter<Driver> + crate::ptm::ArchAdapter<Driver, &'static str>,
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
    /// stage-2 leaf also covers the guest pages fused into the host page, so the
    /// reactor computes one in-kernel auto-step mask per host frame. The mask
    /// delivers every breakpoint sub-page, whose read must reach
    /// [`Self::memory_access`], and auto-steps only the true non-breakpoint
    /// neighbors, so a neighbor data access is retired in the kernel rather than
    /// storming the agent.
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

        // Pass 1: insert every breakpoint and monitor its page-table path. The
        // breakpoint manager arms each page execute-only as it goes; the page
        // table monitor write-protects the path so a page-in / page-out of a
        // pageable target is detected (a kernel target is resident, so its
        // monitor never fires).
        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();
        for spec in breakpoints {
            let cx = (spec.va, spec.root);
            let bp = Breakpoint::new(cx, view).global().with_tag(spec.tag);
            bpm.insert(&vmi, bp)?;
            ptm.monitor(vmi.core(), cx, view, spec.tag)?;
        }

        // Pass 2: set access once per host frame. Skip targets that are not
        // resident at install: a pageable target pages in later, and the
        // singlestep handler masks its frame then. Two breakpoints fused into
        // one 16K host page share a single stage-2 leaf, so apply_frame_access
        // combines the auto-step mask over all co-resident breakpoints rather
        // than clobbering a neighbor's delivery bit.
        let host_shift = vmi.core().info()?.host_page_shift as u32;
        let mut frames = HashSet::<Hfn>::new();
        for spec in breakpoints {
            if let Ok(pa) = vmi.core().translate_address((spec.va, spec.root)) {
                let gfn = Arm64::gfn_from_pa(pa);
                frames.insert(Arm64::hfn_from_gfn(gfn, host_shift));
            }
        }
        for frame in frames {
            Self::apply_frame_access(vmi.core(), breakpoints, frame, view, stealth)?;
        }

        Ok(Self {
            bpm,
            ptm,
            view,
            breakpoints: breakpoints.to_vec(),
            stealth,
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

    /// (Re)applies the stage-2 access for one host `frame` in `view`.
    ///
    /// Scans the retained specs for breakpoints whose target currently
    /// translates into `frame`. With stealth on, sets the frame execute-only
    /// with an auto-step mask that delivers every breakpoint sub-page (so a
    /// PatchGuard read still traps) and auto-steps the fused non-breakpoint
    /// neighbors in the kernel. With stealth off, widens the frame to RWX. A
    /// frame with no currently-resident breakpoint is left untouched.
    fn apply_frame_access(
        vmi: &VmiCore<Driver>,
        breakpoints: &[BreakpointSpec],
        frame: Hfn,
        view: View,
        stealth: bool,
    ) -> Result<(), VmiError> {
        let host_shift = vmi.info()?.host_page_shift as u32;
        let gfns = breakpoints
            .iter()
            .filter_map(|spec| vmi.translate_address((spec.va, spec.root)).ok())
            .map(Arm64::gfn_from_pa)
            .filter(|&gfn| Arm64::hfn_from_gfn(gfn, host_shift) == frame)
            .collect::<Vec<_>>();
        if gfns.is_empty() {
            return Ok(());
        }
        let representative = gfns[0];
        if stealth {
            let mask = Arm64::neighbor_subpage_mask(&gfns, host_shift);
            vmi.set_memory_access_autostep(representative, view, MemoryAccess::X, mask)?;
        }
        else {
            vmi.set_memory_access(representative, view, MemoryAccess::RWX)?;
        }
        Ok(())
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
                // The breakpoint manager has no record of this BRK, so it is
                // either the guest's own (any BRK immediate, e.g. a Windows
                // __fastfail BRK #0xF00x) or a stale event for a BRK already
                // removed. VMI's debug-exception trap (MDCR_EL2.TDE) intercepts
                // every guest BRK, so a live guest BRK must be REINJECTED: a BRK
                // re-traps in place, so single-stepping one loops forever (the
                // instruction never advances). Read the faulting instruction and
                // mask off the imm16 to recognize any BRK, not just our BRK #0.
                let pc = Va(vmi_core::Registers::instruction_pointer(
                    vmi.event().registers(),
                ));
                let is_brk = matches!(vmi.read_u32(pc), Ok(word)
                    if Arm64::is_breakpoint(&word.to_le_bytes()));
                if is_brk {
                    tracing::debug!("foreign guest breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }

                tracing::debug!("ignoring stale breakpoint event");
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
            // A write to a monitored page-table entry: record it so the
            // singlestep handler can detect page-in / page-out. The write must
            // run on the default view (no write-protection there) so it lands.
            // mark_dirty_entry returns false for a non-monitored PA (a stealth
            // neighbor write), which is harmless - no PTM event is produced.
            self.ptm
                .mark_dirty_entry(ma.pa(), self.view, vmi.event().vcpu_id());
            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if ma.access().contains(MemoryAccess::R) {
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("unhandled memory access: {ma:?}");
        }
    }

    /// Handles the singlestep that follows a write to a monitored PTE.
    ///
    /// Drains the dirty entries into page-in / page-out events, lets the
    /// breakpoint manager (de)activate the affected breakpoints, then re-applies
    /// the per-host-frame access for every frame that gained a breakpoint so a
    /// freshly paged-in stealth breakpoint does not storm the agent through its
    /// fused neighbors. A non-PTM singlestep (a stealth write step-over)
    /// produces no events and falls through to the view switch unchanged.
    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Arm64>, VmiError> {
        let events = self
            .ptm
            .process_dirty_entries(vmi.core(), vmi.event().vcpu_id())?;

        let host_shift = vmi.core().info()?.host_page_shift as u32;
        let mut pagein_frames = HashSet::<Hfn>::new();
        for event in &events {
            if let PageTableMonitorEvent::PageIn(update) = event {
                let gfn = Arm64::gfn_from_pa(update.pa);
                pagein_frames.insert(Arm64::hfn_from_gfn(gfn, host_shift));
            }
        }

        self.bpm.handle_ptm_events(vmi.core(), events)?;

        // Re-mask only the frames that gained a breakpoint. A page-out leaves
        // its frame with no active breakpoint, so the breakpoint manager's
        // removal already widened it back to RWX. The one uncovered case is two
        // pageable breakpoints fused into a single host frame where only one
        // pages out: the survivor's frame stays RWX until something re-masks it.
        // That cannot happen with a single target and is deferred per the
        // design's "simplest correct form".
        for frame in pagein_frames {
            Self::apply_frame_access(
                vmi.core(),
                &self.breakpoints,
                frame,
                self.view,
                self.stealth,
            )?;
        }

        Ok(VmiEventResponse::default().with_view(self.view))
    }

    /// Dispatches a VMI event to its handler.
    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Arm64>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            EventReason::Singlestep(_) => self.singlestep(vmi),
        }
    }
}

impl<Driver, Handler> VmiHandler<WindowsOs<Driver>> for ReactorArm64<Driver, Handler>
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture:
        vmi_os_windows::ArchAdapter<Driver> + crate::ptm::ArchAdapter<Driver, &'static str>,
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

        // Drop the page-table write-protections before tearing the view down,
        // mirroring the amd64 reactor. destroy_view would release them anyway,
        // but restoring the page-table pages to RW first keeps teardown
        // self-contained and avoids leaving stale protections if the view ever
        // outlives cleanup.
        self.ptm.unmonitor_all(vmi.core());

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
