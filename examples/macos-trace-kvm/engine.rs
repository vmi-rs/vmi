//! Integrates semantic decoding, same-thread returns and exact IPC
//! observations.

use std::{collections::HashMap, fmt::Write as _};

use vmi::{
    AddressContext, Architecture as _, Gfn, MemoryAccess, Pa, Registers as _, Va, VcpuId, View,
    VmiContext, VmiCore, VmiError, VmiEventResponse,
    arch::arm64::EventReason,
    os::{
        ProcessObject, ThreadObject, VmiOsProcess as _,
        macos::{MacOs, MacOsImage, MacOsProcess},
    },
};

use crate::{
    Arch, Driver, TTBR_BADDR_MASK,
    calls::{Calls, PendingCall, ThreadKey},
    encoding::{AbiKind, AbiType},
    ipc::{HookContext, IpcObservation, IpcTracker, KernelLayout, ProcessIdentity},
    objc::{DispatchStatus, Invocation, ObjcRuntime},
    signatures::{ArgumentLocator, Signatures},
    style::Palette,
    taps::{TapKey, TapKind, Taps},
    values::Values,
};

/// Images whose exports and local symbols feed the decoders.
pub const DECODER_MODULES: &[&str] = &[
    "libobjc.A.dylib",
    "libobjcMsgSend.dylib",
    "CoreFoundation",
    "Foundation",
    "libxpc.dylib",
    "libdispatch.dylib",
];

/// Dispatchers and semantic operations whose entry ABI is checked by the
/// decoder.
pub const SEMANTIC: &[&str] = &[
    "objc_msgSend",
    "objc_msgSendSuper",
    "objc_msgSendSuper2",
    "objc_msgSend_noarg",
    "objc_msgSend_debug",
    "objc_msgSendSuper2_debug",
    "objc_opt_class",
    "objc_opt_self",
    "objc_opt_isKindOfClass",
    "objc_opt_respondsToSelector",
];

/// Maximum aggregate bytes shown from an observed returned storage
/// representation.
const RESULT_LIMIT: usize = 256;

/// Per-process decoding state, including process-specific tagged globals.
struct Decoder {
    /// Live task and address-space identity.
    identity: ProcessIdentity,

    /// Main executable code whose library transitions are traced.
    main: Option<(u64, u64)>,

    /// Cached live runtime metadata for this translation root.
    objc: ObjcRuntime,

    /// Bounded object decoders and checked per-process library layouts.
    values: Values,

    /// Whether private mutation taps have been installed for this root.
    mutations: bool,

    /// Whether the dyld shared cache headers were supplied to the decoders.
    shared_cache: bool,
}

/// Argument positions of `cloneproc` taken from its kernel prototype.
#[derive(Clone, Copy, Debug)]
pub struct ForkArguments {
    /// Argument holding the parent `proc`.
    pub parent: usize,

    /// Argument holding the `cloneproc_flags_t` value.
    pub flags: usize,

    /// Value of the flag that marks an exec rather than a new child.
    pub exec: u64,
}

/// Kernel lifecycle routines located and typed through the kernel profile.
#[derive(Debug, Default)]
pub struct Lifecycle {
    /// Relocated entry instructions and their observation kinds.
    pub taps: Vec<(u64, TapKind)>,

    /// `cloneproc` arguments, present when its fork tap is installed.
    pub fork: Option<ForkArguments>,

    /// Argument holding the `proc` of `mac_proc_notify_exec_complete`.
    pub exec_process: usize,

    /// Argument holding the `proc` of `mac_proc_notify_exit`.
    pub exit_process: usize,
}

/// Holds a serialized original-memory write until shadows and translations
/// agree.
struct Writer {
    /// vCPU allowed to retire the original write.
    vcpu: VcpuId,

    /// Original physical frame changed by that instruction.
    gfn: Gfn,
}

/// Integrates observations without treating API intent or callbacks as returns.
pub struct Engine {
    /// Shared code execution view for related processes.
    system: View,

    /// Main-image execution view for related processes.
    target: View,

    /// Global kernel observation view for unrelated processes.
    observer: View,

    /// Current primary image, advanced only by its observed exec lifecycle.
    primary_identity: Option<ProcessIdentity>,
    /// Revision forcing catalog refresh even when exec reuses an address space.
    primary_revision: u64,

    /// Root-qualified metadata and object readers.
    processes: HashMap<Pa, Decoder>,

    /// Small anchor catalog, not another copy of the complete export map.
    symbols: HashMap<String, u64>,

    /// Global semantic and mutation entry addresses awaiting installation.
    entries: Vec<(u64, TapKind)>,

    /// Whether global kernel and lifecycle taps have been installed.
    initialized: bool,

    /// Whether the primary image catalog has supplied all available anchors.
    symbols_ready: bool,

    /// Independently owned entry and continuation instructions.
    taps: Taps,

    /// Pending stacks indexed by process root and stable thread ID.
    calls: Calls,

    /// Authoritative transport, execution, reply and launch relationships.
    ipc: IpcTracker,

    /// Lifecycle routines relocated and typed through the kernel profile.
    lifecycle: Lifecycle,

    /// Whether receivers of followed messages and children launched for them
    /// are traced too, rather than only the target and its own execs.
    follow: bool,

    /// Writer whose siblings remain paused until its visible step completes.
    writer: Option<Writer>,

    /// Pause references owned by the serialized write, released exactly once.
    paused: Vec<VcpuId>,

    /// Number of formatted semantic or C calls captured at entry.
    pub captured: u64,
}

impl Engine {
    /// Creates per-root decoders and configures kernel observations.
    pub fn new(
        system: View,
        target: View,
        observer: View,
        identity: ProcessIdentity,
        kernel: KernelLayout,
        lifecycle: Lifecycle,
        follow: bool,
    ) -> Self {
        let mut ipc = IpcTracker::default();
        ipc.configure_kernel(kernel);
        ipc.enable_process(identity);
        let decoder = Decoder {
            identity,
            main: None,
            objc: ObjcRuntime::default(),
            values: Values::default(),
            mutations: false,
            shared_cache: false,
        };
        Self {
            system,
            target,
            observer,
            primary_identity: Some(identity),
            primary_revision: 0,
            processes: HashMap::from([(identity.root, decoder)]),
            symbols: HashMap::new(),
            entries: Vec::new(),
            initialized: false,
            symbols_ready: false,
            taps: Taps::new(system, target, observer),
            calls: Calls::default(),
            ipc,
            lifecycle,
            writer: None,
            paused: Vec::new(),
            captured: 0,
            follow,
        }
    }

    /// Reports the live primary image without confusing recycled numeric PIDs.
    pub fn primary_image(&self) -> Option<(ProcessIdentity, u64)> {
        self.primary_identity
            .map(|identity| (identity, self.primary_revision))
    }

    /// Records decoder anchors and selected semantic entry instructions.
    ///
    /// `name` has one leading symbol underscore stripped. Local symbols of the
    /// decoder images arrive here as well as exports.
    pub fn configure_symbol(&mut self, module: &str, name: &str, address: u64) {
        if DECODER_MODULES.contains(&module) {
            let mut consumed = false;
            for decoder in self.processes.values_mut() {
                consumed |= decoder.objc.configure_symbol(name, address);
                consumed |= decoder.values.configure_symbol(name, address);
                consumed |= self
                    .ipc
                    .configure_process_symbol(decoder.identity, name, address);
            }
            if consumed {
                self.symbols.insert(name.to_owned(), address);
            }
        }
        if let Some(name) = SEMANTIC.iter().copied().find(|semantic| *semantic == name) {
            self.entries.push((address, TapKind::Semantic(name)));
        }
        if ObjcRuntime::mutation_symbols().contains(&name) {
            self.entries.push((address, TapKind::Invalidate));
        }
    }

    /// Enables decoder-specific taps once the launch-time image catalog is
    /// complete.
    pub fn symbols_ready(&mut self) {
        self.symbols_ready = true;
    }

    /// Supplies the primary executable range already resolved by the gatherer.
    pub fn main_range(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        root: Pa,
        range: (u64, u64),
    ) -> Result<(), VmiError> {
        if let Some(decoder) = self.processes.get_mut(&root) {
            if decoder.main == Some(range) {
                return Ok(());
            }
            decoder.main = Some(range);
        }
        self.taps.main_image(vmi, root, range.0, range.1)
    }

    /// Tests whether an address belongs to this process's main executable.
    pub fn traced(&self, root: Pa, pc: u64) -> bool {
        self.processes
            .get(&root)
            .and_then(|decoder| decoder.main)
            .is_some_and(|(lo, hi)| pc >= lo && pc < hi)
    }

    /// Selects observation or tracing on an address-space switch.
    pub fn scheduled_view(&self, root: Pa) -> View {
        if self.processes.contains_key(&root) {
            self.system
        }
        else {
            self.observer
        }
    }

    /// Resolves a current process only when its root is not already registered.
    ///
    /// After `proc_exit` detaches the process from its exiting thread, that
    /// thread only runs kernel cleanup, so it is attributed to the kernel.
    fn context(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<HookContext, VmiError> {
        let root = Pa(vmi.registers().ttbr0_el1 & TTBR_BADDR_MASK);
        let thread = vmi.os().current_thread()?;
        let task = thread.task()?.0;
        let process = match self.processes.get(&root) {
            Some(decoder) if decoder.identity.task == task => decoder.identity,
            _ => {
                let system = vmi.os().system_process()?;
                let kernel = system.task()?.map(|kernel| kernel.0);
                match thread.attached_process()? {
                    Some(process) if kernel != Some(task) => identity(&process)?,
                    Some(_) | None => ProcessIdentity {
                        task: kernel.unwrap_or(task),
                        pid: system.id()?.0,
                        root: Pa(0),
                    },
                }
            }
        };
        Ok(HookContext {
            process,
            thread: thread.thread_id()?,
            registers: vmi.registers().regs,
            sp: vmi.registers().stack_pointer(),
            pc: vmi.registers().pc,
        })
    }

    /// Installs startup taps and retries user metadata only at safe user-mode
    /// stops.
    pub fn before_event(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        if !self.initialized {
            let observation = self.ipc.kernel_hooks();
            self.observation(vmi, observation, now, palette)?;
            let lifecycle = std::mem::take(&mut self.lifecycle.taps);
            for &(address, kind) in &lifecycle {
                self.taps.entry(
                    vmi,
                    TapKey {
                        root: None,
                        address,
                    },
                    kind,
                    false,
                )?;
            }
            self.lifecycle.taps = lifecycle;
            self.initialized = true;
        }
        if vmi.registers().pc >> 55 & 1 != 0 {
            return Ok(());
        }
        let root = Pa(vmi.registers().ttbr0_el1 & TTBR_BADDR_MASK);
        if !self.processes.contains_key(&root) {
            return Ok(());
        }
        // A user-mode translation error makes the tracer inject a page-in
        if let Some(va) = self
            .processes
            .get_mut(&root)
            .expect("registered process")
            .values
            .take_page_in()
        {
            return Err(VmiError::Translation(AddressContext::new(Va(va), root)));
        }
        if self.processes[&root].main.is_none() {
            let process = vmi.os().current_process()?;
            let base = process.image_base()?;
            let main = MacOsImage::new(vmi.state(), base, root)
                .segments()?
                .into_iter()
                .find(|segment| segment.name == "__TEXT")
                .map(|segment| {
                    (
                        segment.address.0,
                        segment.address.0.saturating_add(segment.size),
                    )
                });
            if let Some(main) = main {
                self.main_range(vmi, root, main)?;
            }
        }
        if self.symbols_ready {
            let entries = std::mem::take(&mut self.entries);
            for (address, kind) in entries {
                self.taps.entry(
                    vmi,
                    TapKey {
                        root: None,
                        address,
                    },
                    kind,
                    false,
                )?;
            }
            let identity = self.processes[&root].identity;
            let observation = self.ipc.process_hooks(identity);
            self.observation(vmi, observation, now, palette)?;
            if !self.processes[&root].mutations {
                let (addresses, missing) = self.processes[&root].objc.mutation_addresses();
                for line in missing {
                    emit(
                        now,
                        &format!("pid={} {line}", self.processes[&root].identity.pid),
                        palette,
                    );
                }
                for address in addresses {
                    self.taps.entry(
                        vmi,
                        TapKey {
                            root: Some(root),
                            address,
                        },
                        TapKind::Invalidate,
                        false,
                    )?;
                }
                self.processes
                    .get_mut(&root)
                    .expect("registered process")
                    .mutations = true;
            }
            if !self.processes[&root].shared_cache {
                // Non-resident dyld data is retried at a later stop.
                let configured = match vmi.os().current_process()?.shared_cache_base() {
                    Ok(Some(base)) => {
                        let decoder = self.processes.get_mut(&root).expect("registered process");
                        decoder.objc.configure_shared_cache(vmi, base.0)
                    }
                    Ok(None) => {
                        emit(
                            now,
                            &format!(
                                "pid={} dyld shared cache base unavailable: method names in the cache are not decoded",
                                self.processes[&root].identity.pid
                            ),
                            palette,
                        );
                        Ok(())
                    }
                    Err(err) => Err(err),
                };
                match configured {
                    Ok(()) => {
                        self.processes
                            .get_mut(&root)
                            .expect("registered process")
                            .shared_cache = true;
                    }
                    Err(VmiError::Translation(_)) => (),
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(())
    }

    /// Replays original reads and serializes protected code or page-table
    /// writes.
    pub fn memory(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<Option<VmiEventResponse<Arch>>, VmiError> {
        let access = match vmi.event().reason() {
            EventReason::MemoryAccess(access) => access,
            _ => return Ok(None),
        };
        if access.access.contains(MemoryAccess::W) {
            if self.writer.is_some() {
                return Ok(Some(VmiEventResponse::default()));
            }
            let _pause_guard = vmi.core().pause_guard()?;
            let vcpu = vmi.event().vcpu_id();
            for index in 0..vmi.info()?.vcpus {
                let sibling = VcpuId(index);
                if sibling != vcpu {
                    vmi.driver().pause_vcpu(sibling)?;
                    self.paused.push(sibling);
                }
            }
            let view = vmi.event().view().unwrap_or(self.system);
            self.taps.mark_write(access.pa, view, vcpu);
            self.writer = Some(Writer {
                vcpu,
                gfn: Arch::gfn_from_pa(access.pa),
            });
            return Ok(Some(
                VmiEventResponse::singlestep().with_view(vmi.default_view()),
            ));
        }
        if access.access.contains(MemoryAccess::R) {
            return Ok(Some(VmiEventResponse::fast_singlestep(vmi.default_view())));
        }
        Ok(None)
    }

    /// Publishes a serialized write and releases the owned sibling pauses.
    pub fn singlestep(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
        if let Some(writer) = self.writer.take() {
            if writer.vcpu != vmi.event().vcpu_id() {
                self.writer = Some(writer);
                return Ok(VmiEventResponse::default().with_view(self.execution_view(vmi)));
            }
            self.taps.after_write(vmi, writer.vcpu, writer.gfn)?;
            self.resume_siblings(vmi.core())?;
        }
        Ok(VmiEventResponse::default().with_view(self.execution_view(vmi)))
    }

    /// Chooses the correct post-replay partition from the current root and PC.
    fn execution_view(&self, vmi: &VmiContext<MacOs<Driver>>) -> View {
        let root = Pa(vmi.registers().ttbr0_el1 & TTBR_BADDR_MASK);
        if self.traced(root, vmi.registers().pc) {
            self.target
        }
        else {
            self.scheduled_view(root)
        }
    }

    /// Releases exactly the pause references acquired for a protected write.
    fn resume_siblings(&mut self, core: &VmiCore<Driver>) -> Result<(), VmiError> {
        while let Some(vcpu) = self.paused.last().copied() {
            core.driver().resume_vcpu(vcpu)?;
            self.paused.pop();
        }
        Ok(())
    }

    /// Keeps installed shadow pages execute-only when partition permissions
    /// change.
    pub fn library_page(&self, view: View, gfn: Gfn) -> MemoryAccess {
        if self.taps.owns_page(view, gfn) {
            MemoryAccess::X
        }
        else {
            MemoryAccess::RWX
        }
    }

    /// Captures an exported call leaving a traced main executable.
    pub fn call(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        function: &str,
        signatures: &Signatures,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        let context = self.context(vmi)?;
        let root = context.process.root;
        if !self.processes.contains_key(&root) {
            return Ok(());
        }
        let return_pc = canonical(context.registers[30]);
        let key = ThreadKey {
            root: root.0,
            thread: context.thread,
        };
        if self.calls.has_body(key, return_pc, context.sp) {
            return Ok(());
        }
        let decoder = self.processes.get_mut(&root).expect("registered process");
        let prepared = match decoder.objc.invocation(vmi, function)? {
            Some(invocation) => {
                if invocation.method.signature.result.kind == AbiKind::Float
                    || matches!(
                        invocation.method.selector.as_str(),
                        "retain" | "release" | "autorelease"
                    )
                {
                    return Ok(());
                }
                let body = method_call(
                    vmi,
                    &invocation,
                    &mut decoder.objc,
                    &mut decoder.values,
                    palette,
                );
                Some((
                    body,
                    if invocation.status == DispatchStatus::Resolved {
                        Some(invocation.method.signature.result)
                    }
                    else {
                        None
                    },
                ))
            }
            None => signatures
                .prepare_call(
                    vmi,
                    function,
                    &mut decoder.values,
                    &mut decoder.objc,
                    palette,
                )
                .map(|(arguments, result)| {
                    (
                        format!("{} {}", palette.function(function), arguments),
                        Some(result),
                    )
                })
                .or_else(|| Some((palette.function(function), None))),
        };
        let (mut body, result) = match prepared {
            Some(prepared) => prepared,
            None => return Ok(()),
        };
        if self.primary_identity != Some(context.process) {
            body.insert_str(0, &format!("pid={} ", context.process.pid));
        }
        self.captured += 1;
        if return_pc == 0 {
            emit(
                now,
                &format!("{body} (return not observed: null continuation)"),
                palette,
            );
            return Ok(());
        }
        if matches!(
            function,
            "exit" | "_exit" | "_Exit" | "abort" | "pthread_exit"
        ) {
            emit(now, &format!("{body} (nonreturning)"), palette);
            return Ok(());
        }
        self.record(
            vmi,
            key,
            PendingCall {
                entry_pc: context.pc,
                return_pc,
                sp: context.sp,
                timestamp: now,
                body: Some(body),
                result,
                result_buffer: context.registers[8],
                ipc: None,
                ipc_context: None,
                child_of: None,
                tap: None,
                invalidate: false,
            },
            now,
            palette,
        )
    }

    /// Runs an entry observation without exposing or skipping the original
    /// instruction.
    pub fn entry(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        now: f64,
        palette: &Palette,
        signatures: &Signatures,
    ) -> Result<(), VmiError> {
        let root = Pa(vmi.registers().ttbr0_el1 & TTBR_BADDR_MASK);
        let pc = vmi.registers().pc;
        let kind = match self.taps.kind(root, pc) {
            Some(kind) => kind,
            None => return Ok(()),
        };
        let context = self.context(vmi)?;
        let key = ThreadKey {
            root: context.process.root.0,
            thread: context.thread,
        };
        match kind {
            TapKind::Semantic(function) => {
                if self.traced(root, canonical(context.registers[30])) {
                    self.call(vmi, function, signatures, now, palette)?;
                }
            }
            TapKind::Invalidate => {
                if let Some(decoder) = self.processes.get_mut(&root) {
                    decoder.objc.invalidate();
                    decoder.values.invalidate();
                    let return_pc = canonical(context.registers[30]);
                    let tap = if self.traced(root, return_pc) {
                        None
                    }
                    else {
                        Some(self.taps.returning(
                            vmi,
                            TapKey {
                                root: if is_kernel(return_pc) {
                                    None
                                }
                                else {
                                    Some(root)
                                },
                                address: return_pc,
                            },
                            false,
                        )?)
                    };
                    self.record(
                        vmi,
                        key,
                        PendingCall {
                            entry_pc: pc,
                            return_pc,
                            sp: context.sp,
                            timestamp: now,
                            body: None,
                            result: None,
                            result_buffer: 0,
                            ipc: None,
                            ipc_context: None,
                            child_of: None,
                            tap,
                            invalidate: true,
                        },
                        now,
                        palette,
                    )?;
                }
            }
            TapKind::Ipc(kind) => {
                let decode = self
                    .processes
                    .get_mut(&root)
                    .map(|decoder| (&mut decoder.values, &mut decoder.objc, palette));
                let mut observation = self.ipc.entry(vmi, context, kind, decode)?;
                let pending = observation.pending.take();
                self.observation(vmi, observation, now, palette)?;
                if let Some(pending) = pending {
                    let return_pc = canonical(context.registers[30]);
                    let tap = if self.traced(root, return_pc) {
                        None
                    }
                    else {
                        Some(self.taps.returning(
                            vmi,
                            TapKey {
                                root: if is_kernel(return_pc) {
                                    None
                                }
                                else {
                                    Some(root)
                                },
                                address: return_pc,
                            },
                            false,
                        )?)
                    };
                    self.record(
                        vmi,
                        key,
                        PendingCall {
                            entry_pc: pc,
                            return_pc,
                            sp: context.sp,
                            timestamp: now,
                            body: None,
                            result: None,
                            result_buffer: 0,
                            ipc: Some(pending),
                            ipc_context: Some(context),
                            child_of: None,
                            tap,
                            invalidate: false,
                        },
                        now,
                        palette,
                    )?;
                }
            }
            TapKind::Fork => {
                // An exec through cloneproc replaces an image, not a child launch
                if let Some(fork) = self.lifecycle.fork
                    && context.registers[fork.flags] & fork.exec == 0
                    && self.processes.contains_key(&root)
                {
                    let parent = vmi
                        .os()
                        .process(ProcessObject(Va(context.registers[fork.parent])))?;
                    self.record(
                        vmi,
                        key,
                        PendingCall {
                            entry_pc: pc,
                            return_pc: canonical(context.registers[30]),
                            sp: context.sp,
                            timestamp: now,
                            body: None,
                            result: None,
                            result_buffer: 0,
                            ipc: None,
                            ipc_context: None,
                            child_of: Some(identity(&parent)?),
                            tap: None,
                            invalidate: false,
                        },
                        now,
                        palette,
                    )?;
                }
            }
            TapKind::ThreadExit => {
                for call in self.calls.remove_thread(key) {
                    self.abandon(vmi, call, "thread exited", now, palette)?;
                }
                let observation = self.ipc.thread_exited(context.process, context.thread);
                self.observation(vmi, observation, now, palette)?;
            }
            TapKind::Exec => {
                let process = vmi.os().process(ProcessObject(Va(
                    context.registers[self.lifecycle.exec_process]
                )))?;
                let after = identity(&process)?;
                let before = self
                    .processes
                    .values()
                    .find(|decoder| decoder.identity.pid == after.pid)
                    .map(|decoder| decoder.identity);
                if let Some(before) = before {
                    let path = process.image_path()?.unwrap_or_default();
                    let primary = self.primary_identity == Some(before);
                    let observation = self.ipc.process_exec(before, after, context.thread, &path);
                    self.observation(vmi, observation, now, palette)?;
                    self.retire(vmi, before.root, "exec replaced the image", now, palette)?;
                    self.related(after);
                    if primary {
                        self.primary_identity = Some(after);
                        self.primary_revision = self.primary_revision.wrapping_add(1);
                    }
                }
            }
            TapKind::Exit => {
                let process = vmi.os().process(ProcessObject(Va(
                    context.registers[self.lifecycle.exit_process]
                )))?;
                let pid = process.id()?.0;
                let existing = self
                    .processes
                    .values()
                    .find(|decoder| decoder.identity.pid == pid)
                    .map(|decoder| decoder.identity);
                if let Some(existing) = existing {
                    let observation = self.ipc.process_exited(existing);
                    self.observation(vmi, observation, now, palette)?;
                    self.retire(vmi, existing.root, "process exited", now, palette)?;
                }
            }
        }
        Ok(())
    }

    /// Records one frame and retires duplicate or rejected tap ownership.
    fn record(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        key: ThreadKey,
        mut call: PendingCall,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        if call.tap.is_none() {
            let root = Pa(key.root);
            call.tap = Some(self.taps.returning(
                vmi,
                TapKey {
                    root: if is_kernel(call.return_pc) {
                        None
                    }
                    else {
                        Some(root)
                    },
                    address: call.return_pc,
                },
                self.traced(root, call.return_pc),
            )?);
        }
        let (rejected, redundant) = self.calls.enter(key, call);
        if let Some(redundant) = redundant {
            self.taps.release(vmi, redundant)?;
        }
        if let Some(rejected) = rejected {
            self.abandon(vmi, rejected, "pending call depth limit", now, palette)?;
        }
        Ok(())
    }

    /// Completes only exact same-thread and same-stack caller continuations.
    pub fn returned(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        let context = self.context(vmi)?;
        let key = ThreadKey {
            root: context.process.root.0,
            thread: context.thread,
        };
        while let Some((mut call, abandoned)) = self.calls.returning(key, context.pc, context.sp) {
            for abandoned in abandoned {
                self.abandon(vmi, abandoned, "return bypassed this frame", now, palette)?;
            }
            if let Some(tap) = call.tap.take() {
                self.taps.release(vmi, tap)?;
            }
            if call.invalidate
                && let Some(decoder) = self.processes.get_mut(&context.process.root)
            {
                decoder.objc.invalidate();
            }
            if let Some(body) = call.body.take() {
                let result = match (call.result, self.processes.get_mut(&context.process.root)) {
                    (Some(result), Some(decoder)) => result_value(
                        vmi,
                        &result,
                        context.registers[0],
                        call.result_buffer,
                        &mut decoder.values,
                        &mut decoder.objc,
                        palette,
                    ),
                    _ => String::from("? (return type unknown)"),
                };
                emit(
                    call.timestamp,
                    &format!("{body} returned {result}"),
                    palette,
                );
            }
            if let (Some(pending), Some(entry)) = (call.ipc.take(), call.ipc_context) {
                let decode = self
                    .processes
                    .get_mut(&entry.process.root)
                    .map(|decoder| (&mut decoder.values, &mut decoder.objc, palette));
                let observation =
                    self.ipc
                        .returned(vmi, entry, pending, context.registers[0], decode)?;
                self.observation(vmi, observation, now, palette)?;
            }
            if let Some(parent) = call.child_of
                && context.registers[0] != 0
            {
                let child = vmi
                    .os()
                    .thread(ThreadObject(Va(canonical(context.registers[0]))))?
                    .process()?;
                let observation =
                    self.ipc
                        .process_created(parent, identity(&child)?, context.thread);
                self.observation(vmi, observation, now, palette)?;
            }
        }
        Ok(())
    }

    /// Retires scopes and taps rather than inventing values for missing
    /// returns.
    fn abandon(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        mut call: PendingCall,
        reason: &str,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        if let Some(tap) = call.tap.take() {
            self.taps.release(vmi, tap)?;
        }
        if let Some(body) = call.body.take() {
            emit(
                call.timestamp,
                &format!(
                    "{body} (return not observed: {reason}, entry={:#x})",
                    call.entry_pc
                ),
                palette,
            );
        }
        if let (Some(pending), Some(context)) = (call.ipc.take(), call.ipc_context) {
            let observation = self.ipc.abandoned(context, pending, reason);
            self.observation(vmi, observation, now, palette)?;
        }
        Ok(())
    }

    /// Adds a decoder only for an observed related task and image lifetime.
    fn related(&mut self, identity: ProcessIdentity) {
        if self.processes.contains_key(&identity.root) {
            return;
        }
        let mut decoder = Decoder {
            identity,
            main: None,
            objc: ObjcRuntime::default(),
            values: Values::default(),
            mutations: false,
            shared_cache: false,
        };
        for (name, &address) in &self.symbols {
            decoder.objc.configure_symbol(name, address);
            decoder.values.configure_symbol(name, address);
            self.ipc.configure_process_symbol(identity, name, address);
        }
        self.ipc.enable_process(identity);
        self.processes.insert(identity.root, decoder);
    }

    /// Applies verified related identities and installs their requested taps.
    fn observation(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        observation: IpcObservation,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        for line in observation.lines {
            emit(now, &line, palette);
        }
        if self.follow {
            for identity in observation.related {
                self.related(identity);
            }
        }
        for hook in observation.hooks {
            let main = hook
                .root
                .is_some_and(|root| self.traced(root, hook.address));
            self.taps.entry(
                vmi,
                TapKey {
                    root: hook.root,
                    address: hook.address,
                },
                TapKind::Ipc(hook.kind),
                main,
            )?;
        }
        Ok(())
    }

    /// Clears an ended image's calls and private mappings before root reuse.
    fn retire(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        root: Pa,
        reason: &str,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        for call in self.calls.remove_process(root.0) {
            self.abandon(vmi, call, reason, now, palette)?;
        }
        self.taps.remove_process(vmi, root)?;
        if self
            .primary_identity
            .is_some_and(|identity| identity.root == root)
        {
            self.primary_identity = None;
        }
        self.processes.remove(&root);
        Ok(())
    }

    /// Restores original mappings and retires incomplete observations on stop.
    pub fn cleanup(
        &mut self,
        core: &VmiCore<Driver>,
        now: f64,
        palette: &Palette,
    ) -> Result<(), VmiError> {
        for (_, mut call) in self.calls.drain() {
            if let Some(body) = call.body.take() {
                emit(
                    call.timestamp,
                    &format!("{body} (return not observed: tracing stopped)"),
                    palette,
                );
            }
            if let (Some(pending), Some(context)) = (call.ipc.take(), call.ipc_context) {
                for line in self
                    .ipc
                    .abandoned(context, pending, "tracing stopped")
                    .lines
                {
                    emit(now, &line, palette);
                }
            }
        }
        self.taps.clear(core)?;
        self.resume_siblings(core)
    }
}

/// Resolves the task and translation root of an initialized live process.
fn identity(process: &MacOsProcess<'_, Driver>) -> Result<ProcessIdentity, VmiError> {
    let task = process
        .task()?
        .ok_or(VmiError::Other("process has no live task"))?;
    Ok(ProcessIdentity {
        task: task.0,
        pid: process.id()?.0,
        root: process.translation_root()?,
    })
}

/// Extracts a virtual address without claiming to validate its pointer
/// signature.
fn canonical(raw: u64) -> u64 {
    Arch::canonical_address(raw).0
}

/// Tests the user/kernel address discriminator used by the guest geometry.
fn is_kernel(address: u64) -> bool {
    address >> 55 & 1 != 0
}

/// Interleaves fixed argument values with the selected method's selector
/// pieces.
fn method_call(
    vmi: &VmiContext<MacOs<Driver>>,
    invocation: &Invocation,
    objc: &mut ObjcRuntime,
    values: &mut Values,
    palette: &Palette,
) -> String {
    let mut body = String::new();
    let name = objc
        .info(invocation.class)
        .map(|info| info.name.as_str())
        .unwrap_or(if invocation.receiver == 0 { "nil" } else { "?" });
    if invocation.is_class {
        let _ = write!(body, "+[{name} ");
    }
    else {
        let _ = write!(body, "-[{}<0x{:x}> ", name, invocation.receiver);
    }
    if invocation.status != DispatchStatus::Resolved {
        body.push_str(&palette.function(&invocation.method.selector));
        let note = match invocation.status {
            DispatchStatus::Resolved => "",
            DispatchStatus::Nil => "nil receiver, argument types unavailable",
            DispatchStatus::Unresolved => "argument types unavailable",
            DispatchStatus::Forwarded => "forwarded, argument types unavailable",
            DispatchStatus::UnsupportedLayout => "unsupported runtime layout",
        };
        let _ = write!(body, "] ({note})");
        return body;
    }
    let mut pieces = invocation.method.selector.split(':');
    let mut locator = ArgumentLocator::with_general(invocation.argument_base);
    let arguments = &invocation.method.signature.arguments[2..];
    if arguments.is_empty() {
        body.push_str(&palette.function(&invocation.method.selector));
    }
    for (index, ty) in arguments.iter().enumerate() {
        if index != 0 {
            body.push(' ');
        }
        let name = pieces.next().unwrap_or("arg");
        body.push_str(&palette.arg_name(name));
        body.push(':');
        body.push_str(&locator.argument(vmi, ty, values, objc, palette));
    }
    body.push(']');
    body
}

/// Formats the observed ABI result without mistaking a GPR for a floating
/// result.
fn result_value(
    vmi: &VmiContext<MacOs<Driver>>,
    ty: &AbiType,
    raw: u64,
    indirect: u64,
    values: &mut Values,
    objc: &mut ObjcRuntime,
    palette: &Palette,
) -> String {
    match ty.kind {
        AbiKind::Unknown => String::from("? (return type unknown)"),
        AbiKind::Void => String::from("void"),
        AbiKind::Float => String::from("? (floating-point result omitted)"),
        AbiKind::Aggregate => {
            let length = usize::try_from(ty.size)
                .unwrap_or(RESULT_LIMIT)
                .min(RESULT_LIMIT);
            let mut bytes = vec![0_u8; length];
            if ty.size <= 16 {
                let registers = vmi.registers();
                let words = [
                    registers.regs[0].to_le_bytes(),
                    registers.regs[1].to_le_bytes(),
                ];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = words[index / 8][index % 8];
                }
            }
            else if vmi.read(Va(canonical(indirect)), &mut bytes).is_err() {
                return String::from("? (aggregate result inaccessible)");
            }
            let mut out = String::from("{bytes=");
            for byte in bytes {
                let _ = write!(out, "{byte:02x}");
            }
            if ty.size > RESULT_LIMIT as u64 {
                out.push_str("... (truncated)");
            }
            out.push('}');
            out
        }
        _ => values.render(vmi, ty, raw, objc, palette),
    }
}

/// Writes one timestamped observed record without altering payload strings.
fn emit(now: f64, body: &str, palette: &Palette) {
    let timestamp = palette.timestamp(&format!("[{now:08.3}]"));
    println!("{timestamp} {body}");
}
