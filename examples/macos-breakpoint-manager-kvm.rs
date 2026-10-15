//! Demonstrates the [`BreakpointManager`] and [`PageTableMonitor`] by
//! monitoring process lifecycle and file operations on a live macOS KVM guest.
//!
//! Usage: `macos-breakpoint-manager-kvm [PID] [CACHE] [HITS]`
//! Defaults: the first QEMU process, `cache`, and unlimited hits (`0`).
//! Ctrl-C restores the original memory view and detaches from the guest.
//!
//! The kernel hook signatures were verified on macOS 27.0.1 (26A434).
//! Creation notifications and write requests do not imply successful syscall
//! completion. See the individual handlers for their observation boundaries.
//!
//! [`BreakpointManager`]: vmi::utils::bpm::BreakpointManager
//! [`PageTableMonitor`]: vmi::utils::ptm::PageTableMonitor

#[cfg(target_arch = "aarch64")]
use anyhow::Error;

/// Implements the native arm64 KVM monitoring workflow.
#[cfg(target_arch = "aarch64")]
mod example {
    use std::{
        io::ErrorKind,
        os::fd::AsFd,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use anyhow::{Context as _, Error};
    use isr::{
        Profile,
        cache::IsrCache,
        macros::{Field, offsets, symbols},
    };
    use vmi::{
        AddressContext, Architecture as _, Gfn, MemoryAccess, Registers as _, Va, VcpuId, View,
        VmiContext, VmiCore, VmiError, VmiEventResponse, VmiHandler, VmiSession,
        arch::arm64::{Arm64, EventMonitor, EventReason, Granule16KVa47},
        driver::kvm::VmiKvmDriver,
        os::{
            ProcessObject, VmiOsProcess as _,
            macos::{MacOs, MacOsExt as _, MacOsOpenFile, MacOsVnode},
        },
        utils::{
            bpm::{Breakpoint, BreakpointController, BreakpointManager},
            ptm::PageTableMonitor,
        },
    };

    /// Selects the 16KB translation geometry used by this macOS guest.
    type Arch = Arm64<Granule16KVa47>;

    /// Owns the native KVM connection and its per-vCPU pause references.
    type Driver = VmiKvmDriver<Arch>;

    symbols! {
        /// Identifies the kernel routines monitored by this example.
        #[derive(Debug)]
        pub struct Symbols {
            dtrace_proc_fork: u64,
            mac_proc_notify_exec_complete: u64,
            mac_proc_notify_exit: u64,
            mac_vnode_notify_create: u64,
            vn_write: u64,
        }
    }

    offsets! {
        /// Locates write-request metadata in the matching kernel profile.
        #[derive(Debug)]
        pub struct Offsets {
            struct uio {
                uio_offset: Field,
                uio_resid_64: Field,
            }
        }
    }

    /// Holds per-VM breakpoint ownership and committed-write monitoring state.
    pub struct Monitor {
        /// Becomes visible inside callbacks even while KVM drains a busy ring.
        terminate_flag: Arc<AtomicBool>,

        /// Contains executable shadow pages and write-protected page tables.
        view: View,

        /// Owns patches independently of the process currently executing them.
        bpm: BreakpointManager<BreakpointController<Driver>>,

        /// Tracks all descriptor paths leading to the monitored routines.
        ptm: PageTableMonitor<Driver>,

        /// Retains registration identities for stale events and partial
        /// cleanup.
        targets: [(&'static str, AddressContext); 5],

        /// Supplies layout offsets without embedding build-specific constants.
        offsets: Offsets,

        /// Counts hits by the native vCPU IDs assigned when the driver
        /// attached.
        hits: Vec<u64>,

        /// Counts all managed hits, including events whose metadata read fails.
        total_hits: u64,

        /// Stops after this many hits when the value is nonzero.
        hit_limit: u64,

        /// Allows only this vCPU to retire a write before shared state is
        /// updated.
        writer: Option<(VcpuId, Gfn)>,

        /// Retains exactly the sibling pause references acquired by this
        /// monitor.
        paused: Vec<VcpuId>,

        /// Preserves the first callback failure until the command boundary.
        error: Option<VmiError>,

        /// Makes queued events resume in the original view during cleanup.
        stopping: bool,
    }

    impl Monitor {
        /// Installs the lifecycle and file hooks while guest execution is
        /// paused.
        pub fn new(
            session: &VmiSession<MacOs<Driver>>,
            profile: &Profile,
            terminate_flag: Arc<AtomicBool>,
            hit_limit: u64,
        ) -> Result<Self, VmiError> {
            let pause_guard = session.pause_guard()?;
            let vmi = pause_guard.state();
            let kernel_image_base = vmi.os().kernel_image_base()?;
            let root = vmi.registers().translation_root(kernel_image_base);
            tracing::info!(%kernel_image_base, %root);

            // XNU profiles contain unslid addresses, not Windows-style RVAs.
            // Relocate each symbol through its containing kernel segment.
            let symbols = Symbols::new(profile)?;
            let offsets = Offsets::new(profile)?;
            let target = |address| -> Result<AddressContext, VmiError> {
                let va = vmi.os().relocate_kernel_address(address)?;
                vmi.core().translate_address((va, root))?;
                Ok(AddressContext::new(va, root))
            };
            let targets = [
                ("dtrace_proc_fork", target(symbols.dtrace_proc_fork)?),
                (
                    "mac_proc_notify_exec_complete",
                    target(symbols.mac_proc_notify_exec_complete)?,
                ),
                (
                    "mac_proc_notify_exit",
                    target(symbols.mac_proc_notify_exit)?,
                ),
                (
                    "mac_vnode_notify_create",
                    target(symbols.mac_vnode_notify_create)?,
                ),
                ("vn_write", target(symbols.vn_write)?),
            ];
            let vcpus = vmi.info()?.vcpus as usize;
            let view = vmi.create_view(MemoryAccess::RWX)?;
            let mut monitor = Self {
                terminate_flag,
                view,
                bpm: BreakpointManager::new(),
                ptm: PageTableMonitor::new(),
                targets,
                offsets,
                hits: vec![0; vcpus],
                total_hits: 0,
                hit_limit,
                writer: None,
                paused: Vec::with_capacity(vcpus.saturating_sub(1)),
                error: None,
                stopping: false,
            };

            if let Err(err) = monitor.install(session) {
                if let Err(err) = monitor.stop(session) {
                    tracing::error!(%err, "Failed to clean up incomplete installation");
                }
                return Err(err);
            }
            tracing::info!(
                ?view,
                tables = monitor.ptm.monitored_tables(),
                "Monitor installed"
            );
            Ok(monitor)
        }

        /// Registers every translation path before any vCPU enters the patched
        /// view.
        fn install(&mut self, session: &VmiSession<MacOs<Driver>>) -> Result<(), VmiError> {
            session.monitor_enable(EventMonitor::Breakpoint)?;
            session.monitor_enable(EventMonitor::Singlestep)?;

            // The controller keeps patched execution copies of code pages.
            // Reads use the original view so they do not observe our BRKs.
            // Writes need a visible step so the copy can be refreshed afterward.
            // The page-table monitor also protects each routine's translation
            // path, allowing the manager to follow page-out/page-in transitions.
            for (symbol, target) in self.targets {
                self.ptm.monitor(session, target, self.view, symbol)?;
                let breakpoint = Breakpoint::new(target, self.view).global().with_tag(symbol);
                self.bpm.insert(session, breakpoint)?;
                tracing::info!(symbol, va = %target.va, root = %target.root, "Breakpoint installed");
            }
            session.switch_to_view(self.view)
        }

        /// Handles original-page reads and serializes monitored writes.
        #[tracing::instrument(skip_all)]
        fn memory_access(
            &mut self,
            vmi: &VmiContext<MacOs<Driver>>,
        ) -> Result<VmiEventResponse<Arch>, VmiError> {
            let access = match vmi.event().reason() {
                EventReason::MemoryAccess(access) => access,
                _ => return Err(VmiError::Other("expected a memory access event")),
            };
            tracing::trace!(pa = %access.pa, va = %access.va, access = %access.access);

            if access.access.contains(MemoryAccess::W) {
                // A write can modify either a page table or original code.
                // Keep siblings paused until the writer's visible single-step
                // completes and both forms of monitoring have been updated.
                if self.writer.is_some() {
                    // This queued sibling event is acknowledged while its CPU
                    // remains paused. Its protected write retries after release.
                    return Ok(VmiEventResponse::default());
                }
                let _pause_guard = vmi.core().pause_guard()?;
                let vcpu = vmi.event().vcpu_id();
                for id in 0..self.hits.len() {
                    let sibling = VcpuId(id as u16);
                    if sibling != vcpu {
                        vmi.driver().pause_vcpu(sibling)?;
                        self.paused.push(sibling);
                    }
                }
                self.ptm.mark_dirty_entry(access.pa, self.view, vcpu);
                self.writer = Some((vcpu, Arch::gfn_from_pa(access.pa)));
                Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
            }
            else if access.access.contains(MemoryAccess::R) {
                // KVM performs this step without delivering another callback.
                // The instruction reads original bytes, then returns to our view.
                Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
            }
            else {
                Err(VmiError::Other("unexpected monitored memory access"))
            }
        }

        /// Dispatches tagged stops and preserves guest-owned breakpoint
        /// exceptions.
        #[tracing::instrument(skip_all, fields(vcpu, pid, process))]
        fn interrupt(
            &mut self,
            vmi: &VmiContext<MacOs<Driver>>,
        ) -> Result<VmiEventResponse<Arch>, VmiError> {
            let interrupt = match vmi.event().reason() {
                EventReason::Interrupt(interrupt) => interrupt,
                _ => return Err(VmiError::Other("expected a breakpoint event")),
            };
            if interrupt.interrupt.esr & 0xffff != 0 {
                return Ok(VmiEventResponse::reinject_interrupt());
            }
            let tag = match self.bpm.get_by_event(vmi.event(), ()) {
                Some(breakpoint) => breakpoint.tag(),
                None => {
                    let pc = Va(vmi.registers().instruction_pointer());
                    let instruction = vmi.core().read_u32(Arch::pa_in_gfn(interrupt.gfn, pc))?;
                    if Self::is_brk(instruction) {
                        tracing::warn!(%pc, "Guest breakpoint, reinjecting");
                        return Ok(VmiEventResponse::reinject_interrupt());
                    }
                    if self.owns_stop(vmi) {
                        // A previously queued event may outlive its patch.
                        return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                    }
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
            };

            self.total_hits += 1;
            self.hits[usize::from(vmi.event().vcpu_id().0)] += 1;
            let span = tracing::Span::current();
            span.record("vcpu", vmi.event().vcpu_id().0);
            let process = vmi
                .os()
                .current_process()
                .and_then(|process| Ok((process.id()?, process.name()?)));
            match process {
                Ok((process_id, process_name)) => {
                    span.record("pid", process_id.0);
                    span.record("process", process_name);
                }
                Err(err) => tracing::warn!(%err, "Current process context unavailable"),
            }

            match tag {
                "dtrace_proc_fork" => self.dtrace_proc_fork(vmi)?,
                "mac_proc_notify_exec_complete" => self.mac_proc_notify_exec_complete(vmi)?,
                "mac_proc_notify_exit" => self.mac_proc_notify_exit(vmi)?,
                "mac_vnode_notify_create" => self.mac_vnode_notify_create(vmi)?,
                "vn_write" => self.vn_write(vmi)?,
                _ => return Err(VmiError::Other("unknown breakpoint tag")),
            }

            // Unlike INT3, Arm BRK leaves PC at the replaced instruction.
            // Do not advance PC. Execute the original instruction in the
            // default view, then let KVM return this vCPU to the patched view.
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }

        /// Applies committed mapping and code changes before releasing
        /// siblings.
        #[tracing::instrument(skip_all)]
        fn singlestep(
            &mut self,
            vmi: &VmiContext<MacOs<Driver>>,
        ) -> Result<VmiEventResponse<Arch>, VmiError> {
            let (writer, gfn) = match self.writer {
                Some(writer) => writer,
                None => return Err(VmiError::Other("unexpected single-step completion")),
            };
            if writer != vmi.event().vcpu_id() {
                return Err(VmiError::Other("single-step completed on the wrong vCPU"));
            }
            let _pause_guard = vmi.core().pause_guard()?;
            let updates = self.ptm.process_dirty_entries(vmi, writer)?;
            if !updates.is_empty() {
                tracing::debug!(?updates, "Monitored mappings changed");
                self.bpm.handle_ptm_events(vmi, updates)?;
            }
            self.bpm.refresh_page(vmi, gfn, self.view)?;
            self.writer = None;
            self.resume_siblings(vmi.core())?;
            Ok(VmiEventResponse::default().with_view(self.view))
        }

        /// Reports an initialized child before its inherited image may be
        /// replaced.
        #[tracing::instrument(skip_all)]
        fn dtrace_proc_fork(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<(), VmiError> {
            //
            // void dtrace_proc_fork(proc_t parent, proc_t child, int spawn);
            //
            // X0/X1 are initialized proc objects. X2 distinguishes ordinary
            // fork from spawn. The call precedes spawn's image activation, so
            // the child's name still describes its inherited image.
            //
            let parent = Va(vmi.os().function_argument(0)?);
            let child = Va(vmi.os().function_argument(1)?);
            let spawn = vmi.os().function_argument(2)? as u32 != 0;
            let parent_process = vmi.os().process(ProcessObject(parent))?;
            let process = vmi.os().process(ProcessObject(child))?;
            let process_id = process.id()?;
            let parent_id = parent_process.id()?;
            let inherited_name = process.name()?;
            let kind = if spawn { "posix_spawn" } else { "fork" };
            tracing::info!(%process_id, %parent_id, %child, inherited_name, kind, "Process created");
            Ok(())
        }

        /// Reports the image visible at the kernel's exec-completion
        /// notification.
        #[tracing::instrument(skip_all)]
        fn mac_proc_notify_exec_complete(
            &self,
            vmi: &VmiContext<MacOs<Driver>>,
        ) -> Result<(), VmiError> {
            //
            // void mac_proc_notify_exec_complete(proc_t process);
            //
            // Exec can replace the proc object while preserving its PID.
            // Observe the supplied object, not the creation-time proc pointer.
            // This notification does not assert a successful syscall return.
            //
            let object = Va(vmi.os().function_argument(0)?);
            let process = vmi.os().process(ProcessObject(object))?;
            let process_id = process.id()?;
            let parent_id = process.parent_id()?;
            let name = process.name()?;
            let image_path = process.image_path()?;
            tracing::info!(%process_id, %parent_id, %object, name, ?image_path, "Process exec complete");
            Ok(())
        }

        /// Reports final process cleanup without counting exec's shadow-proc
        /// teardown.
        #[tracing::instrument(skip_all)]
        fn mac_proc_notify_exit(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<(), VmiError> {
            //
            // void mac_proc_notify_exit(proc_t process);
            //
            // The caller excludes old proc objects discarded during exec.
            // The executable vnode is still attached here, but this event
            // precedes zombie reaping and does not promise a live address space.
            //
            let object = Va(vmi.os().function_argument(0)?);
            let process = vmi.os().process(ProcessObject(object))?;
            let process_id = process.id()?;
            let parent_id = process.parent_id()?;
            let name = process.name()?;
            tracing::info!(%process_id, %parent_id, %object, name, "Process exiting");
            Ok(())
        }

        /// Reports a kernel creation notification with its initialized result
        /// vnode.
        #[tracing::instrument(skip_all)]
        fn mac_vnode_notify_create(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<(), VmiError> {
            //
            // int mac_vnode_notify_create(vfs_context_t ctx, mount_t mount,
            //     vnode_t directory, vnode_t vnode, struct componentname *name);
            //
            // X3 is a vnode, not a vnode output slot. The filesystem operation
            // has returned, but policy callbacks can still reject the request.
            // Compound opens can also notify for an existing vnode. Therefore
            // this event is not an unconditional successful-create assertion.
            //
            let object = Va(vmi.os().function_argument(3)?);
            let vnode = MacOsVnode::new(vmi.state(), object);
            let path = vnode.path()?;
            tracing::info!(%object, ?path, "File creation notification");
            Ok(())
        }

        /// Reports descriptor-backed vnode write requests without scanning file
        /// tables.
        #[tracing::instrument(skip_all)]
        fn vn_write(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<(), VmiError> {
            //
            // int vn_write(struct fileproc *file, struct uio *uio, int flags,
            //     vfs_context_t context);
            //
            // Write, pwrite, and writev reach this shared fileops entry with
            // a referenced fileproc and a kernel-resident uio. The residual is
            // requested bytes, not bytes transferred. Positional writes supply
            // an offset. Other writes acquire their effective offset later.
            //
            let fileproc = Va(vmi.os().function_argument(0)?);
            let uio = Va(vmi.os().function_argument(1)?);
            let flags = vmi.os().function_argument(2)? as u32;

            // This hook has no descriptor number. -1 marks that unavailable
            // identity in the existing object wrapper and is never logged.
            let file = MacOsOpenFile::new(vmi.state(), -1, fileproc);
            let path = file.path()?;
            let requested_bytes = vmi.read_u64(uio + self.offsets.uio.uio_resid_64.offset())?;
            let offset = if flags & 1 != 0 {
                Some(vmi.read_u64(uio + self.offsets.uio.uio_offset.offset())? as i64)
            }
            else {
                None
            };
            tracing::info!(%fileproc, ?path, requested_bytes, ?offset, "File write requested");
            Ok(())
        }

        /// Selects the Windows-style memory, interrupt, and single-step
        /// handlers.
        fn dispatch(
            &mut self,
            vmi: &VmiContext<MacOs<Driver>>,
        ) -> Result<VmiEventResponse<Arch>, VmiError> {
            match vmi.event().reason() {
                EventReason::MemoryAccess(_) => self.memory_access(vmi),
                EventReason::Interrupt(_) => self.interrupt(vmi),
                EventReason::Singlestep(_) => self.singlestep(vmi),
                _ => Err(VmiError::Other("unexpected event in breakpoint example")),
            }
        }

        /// Recognizes any Arm BRK immediate in an original instruction word.
        fn is_brk(instruction: u32) -> bool {
            instruction & 0xffe0001f == 0xd4200000
        }

        /// Identifies managed addresses even when a queued stop outlives its
        /// patch.
        fn owns_stop(&self, vmi: &VmiContext<MacOs<Driver>>) -> bool {
            vmi.event().view() == Some(self.view)
                && self
                    .targets
                    .iter()
                    .any(|(_, target)| target.va == Va(vmi.registers().instruction_pointer()))
        }

        /// Resumes queued managed stops while preserving genuine guest
        /// exceptions.
        fn resume_unmonitored(&self, vmi: &VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
            if let EventReason::Interrupt(interrupt) = vmi.event().reason() {
                let pc = Va(vmi.registers().instruction_pointer());
                let original = vmi.core().read_u32(Arch::pa_in_gfn(interrupt.gfn, pc));
                if interrupt.interrupt.esr & 0xffff != 0
                    || !self.owns_stop(vmi)
                    || original.is_err()
                    || original.is_ok_and(Self::is_brk)
                {
                    return VmiEventResponse::reinject_interrupt().with_view(vmi.default_view());
                }
            }
            VmiEventResponse::default().with_view(vmi.default_view())
        }

        /// Checks cancellation inside busy driver callbacks as well as between
        /// waits.
        fn should_stop(&self) -> bool {
            self.stopping
                || self.error.is_some()
                || self.terminate_flag.load(Ordering::Relaxed)
                || (self.hit_limit != 0 && self.total_hits >= self.hit_limit)
        }

        /// Releases acquired sibling pauses without discarding a failed
        /// release.
        fn resume_siblings(&mut self, core: &VmiCore<Driver>) -> Result<(), VmiError> {
            while let Some(vcpu) = self.paused.last().copied() {
                core.driver().resume_vcpu(vcpu)?;
                self.paused.pop();
            }
            Ok(())
        }

        /// Propagates callback errors through an explicit, interruptible event
        /// loop.
        fn run(&mut self, session: &VmiSession<MacOs<Driver>>) -> Result<(), VmiError> {
            while self.poll().is_none() {
                match session.wait_for_event(Duration::from_millis(200), self) {
                    Ok(()) => {}
                    Err(VmiError::Timeout) => {}
                    Err(VmiError::Io(err)) if err.kind() == ErrorKind::Interrupted => {}
                    Err(err) => return Err(err),
                }
            }
            match self.error.take() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        /// Restores original mappings and permissions before draining queued
        /// events.
        fn stop(&mut self, session: &VmiSession<MacOs<Driver>>) -> Result<(), VmiError> {
            let _pause_guard = session.pause_guard()?;
            self.stopping = true;
            session.monitor_disable(EventMonitor::Breakpoint)?;
            session.monitor_disable(EventMonitor::Singlestep)?;
            session.switch_to_view(session.default_view())?;
            self.resume_siblings(session.core())?;
            self.writer = None;
            for (_, target) in self.targets {
                self.ptm.unmonitor_by_force(session, target, self.view)?;
            }
            self.bpm.clear(session)?;
            session.destroy_view(self.view)?;
            while session.events_pending() > 0 {
                session.wait_for_event(Duration::ZERO, self)?;
            }
            tracing::info!(hits = self.total_hits, per_vcpu = ?self.hits, "Monitor removed");
            Ok(())
        }
    }

    impl VmiHandler<MacOs<Driver>> for Monitor {
        /// Leaves cleanup errors observable at the native command boundary.
        type Output = ();

        /// Flushes stale translations and acknowledges every event, including
        /// failures.
        fn handle_event(&mut self, vmi: VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
            vmi.flush_v2p_cache();
            if self.should_stop() {
                return self.resume_unmonitored(&vmi);
            }
            match self.dispatch(&vmi) {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!(%err, "Monitor handler failed");
                    self.error.get_or_insert(err);
                    self.resume_unmonitored(&vmi)
                }
            }
        }

        /// Ends monitoring on cancellation, callback failure, or the exact hit
        /// limit.
        fn poll(&mut self) -> Option<Self::Output> {
            self.should_stop().then_some(())
        }
    }

    /// Finds the QEMU process using the process-list example's native
    /// convention.
    fn find_qemu_pid() -> Result<i32, VmiError> {
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let pid = match entry.file_name().to_string_lossy().parse::<i32>() {
                Ok(pid) => pid,
                Err(err) => {
                    let _ = err;
                    continue;
                }
            };
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                && comm.trim_end().starts_with("qemu-system")
            {
                return Ok(pid);
            }
        }
        Err(VmiError::Other("no qemu-system process found"))
    }

    /// Loads the matching Darwin profile and runs the native monitoring
    /// session.
    pub fn main() -> Result<(), Error> {
        let mut args = std::env::args().skip(1);
        let first = args.next();
        if first.as_deref() == Some("--help") {
            println!("Usage: macos-breakpoint-manager-kvm [PID] [CACHE] [HITS]");
            println!("Defaults: first QEMU process, cache, unlimited hits (0)");
            return Ok(());
        }
        let pid = match first {
            Some(first) => first.parse::<i32>().context("invalid QEMU pid")?,
            None => find_qemu_pid()?,
        };
        let cache = args.next().unwrap_or_else(|| String::from("cache"));
        let hit_limit = match args.next() {
            Some(argument) => argument.parse::<u64>().context("invalid hit limit")?,
            None => 0,
        };
        if args.next().is_some() {
            anyhow::bail!("too many arguments");
        }
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_target(false)
            .init();
        let terminate_flag = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signal_hook::flag::register(signal, terminate_flag.clone())?;
        }
        if kvm::host_page_size() as u64 != Arch::PAGE_SIZE {
            anyhow::bail!("this example requires matching 16K host and guest pages");
        }

        // The native KVM bootstrap differs from the Xen/Windows common helper.
        // Keep the profile tied to the guest's Darwin version and kernel UUID.
        let fds = kvm::attach::from_pid(pid)?;
        let driver = Driver::new(fds.vm.as_fd(), fds.vcpus)?;
        let mut core = VmiCore::new(driver)?;
        core.disable_gfn_cache();
        let kernel_info = {
            let _pause_guard = core.pause_guard()?;
            let registers = core.registers(VcpuId(0))?;
            MacOs::find_kernel(&core, &registers)?.context("kernel not found")?
        };
        let isr = IsrCache::new(cache)?;
        let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
        let profile = entry.profile()?;
        let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
        let session = VmiSession::new(&core, &os);
        let mut monitor = Monitor::new(&session, &profile, terminate_flag, hit_limit)?;
        let result = monitor.run(&session);
        let cleanup = monitor.stop(&session);

        // Close the native session even if callback handling or cleanup failed.
        // Session::handle has a void cleanup hook and cannot report this error.
        drop(core);
        result?;
        cleanup?;
        Ok(())
    }
}

/// Runs the example on a native arm64 host.
#[cfg(target_arch = "aarch64")]
fn main() -> Result<(), Error> {
    example::main()
}

/// Reports the native-host requirement without attaching to a guest.
#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("This example requires an aarch64 host and a macOS KVM guest.");
}
