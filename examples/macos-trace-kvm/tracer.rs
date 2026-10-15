//! View-partitioning tracer that detects calls out of the target image and
//! resolves them against the exports of the process's dyld images.

use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use vmi::{
    Architecture as _, MemoryAccess, Pa, Va, View, VmiContext, VmiCore, VmiError, VmiEventResponse,
    VmiHandler, VmiSession,
    arch::arm64::{EventMonitor, EventReason, Interrupt, SystemRegister},
    driver::VmiVmControl as _,
    os::{
        ProcessId, VmiOsImage as _, VmiOsProcess as _, VmiOsUserModule as _,
        macos::{MacOs, MacOsImage, MacOsProcess},
    },
};

use crate::{
    Arch, Driver, TTBR_BADDR_MASK,
    engine::{Engine, SEMANTIC},
    ipc::ProcessIdentity,
    signatures::Signatures,
    style::{Palette, stdout_supports_color},
};

/// Passes to wait for one injected page-in before giving up on a module's
/// exports.
const PAGEIN_STALL_LIMIT: u32 = 4096;

/// Hard cap on total gather passes, guaranteeing the gather terminates even
/// if a page never becomes resident.
const MAX_GATHER_PASSES: u32 = 200_000;

/// Passes to wait for the dyld image list, or for an injected page-in of one
/// of its pages, before giving up on enumerating modules.
const CAPTURE_STALL_LIMIT: u32 = 4096;

/// Images whose functions are not printed. Their string, memory and
/// allocation helpers, and the Objective-C runtime's reference counting and
/// property accessors, dominate the output of most programs. Message sends
/// live in `libobjcMsgSend.dylib` and are still printed.
const IGNORED_MODULES: &[&str] = &[
    "libsystem_platform.dylib",
    "libsystem_malloc.dylib",
    "libobjc.A.dylib",
];

/// Images whose local symbols name the private functions and data the
/// decoders use. Foundation is a decoder image too, but its private layouts
/// come from Objective-C metadata, so its large symbol table is not read.
const LOCAL_MODULES: &[&str] = &[
    "libobjc.A.dylib",
    "libobjcMsgSend.dylib",
    "CoreFoundation",
    "libxpc.dylib",
    "libdispatch.dylib",
];

/// Returns true if `va` is a kernel (`TTBR1_EL1`) address.
fn is_kernel(va: u64) -> bool {
    (va >> 55) & 1 != 0
}

/// A resolved export: the image that provides it and the function name.
struct Export {
    /// File name of the providing image.
    module: String,

    /// Exported symbol name without the leading underscore of C symbols.
    function: String,
}

/// Per-module export-gather state accumulated across faults.
struct ModuleDump {
    /// File name of the image, used to qualify resolved export names.
    name: String,

    /// Address of the Mach-O header of the image.
    base: Va,

    /// Set once the image's exports have been read into the export map.
    done: bool,

    /// Terminal note when the exports could not be read.
    note: Option<&'static str>,

    /// Set once the image's local symbols have been handed to the engine, or
    /// from the start for images whose locals no decoder needs.
    locals_done: bool,

    /// Last VA a page-fault was injected for, so retries inject once per page
    /// instead of hammering a page-in already in flight.
    injected_va: Option<Va>,

    /// Passes spent waiting on `injected_va` to become resident.
    stalls: u32,
}

/// Semantic tracer with an owned teardown pause through view destruction.
pub struct Tracer<'a> {
    /// Outlives the handler and permits balanced cleanup on exceptional exits.
    core: &'a VmiCore<Driver>,

    /// Retains one VM-wide pause until all instrumented views are destroyed.
    stop_paused: bool,

    /// Unmodified RWX mapping; selected when the target is not scheduled.
    default: View,

    /// View in which non-target (library and kernel) code is executable.
    system: View,

    /// View in which the target image's own code is executable.
    target: View,

    /// Target process translation root (`pmap->ttep`), the table that
    /// `TTBR0_EL1` selects while the target runs.
    target_root: Pa,

    /// Target process ID, used to locate the process for module enumeration.
    target_pid: ProcessId,
    /// Last observed primary exec revision used to build the image catalog.
    target_revision: u64,

    /// VA range `[lo, hi)` of the `__TEXT` segment of the main executable.
    /// Code in this range runs in the target view, so its calls into other
    /// images are reported. `None` until a fault reads it.
    traced_range: Option<(u64, u64)>,

    /// Resolved exports across all images, indexed by absolute VA, for fast
    /// call-target lookup.
    exports: HashMap<u64, Export>,

    /// Per-module export-gather state. `None` until the main executable
    /// first runs and a fault captures the dyld image list.
    modules: Option<Vec<ModuleDump>>,

    /// Last VA a page-fault was injected for while reading the main
    /// executable or the image list, so a retry injects once per page
    /// instead of hammering a page-in in flight.
    capture_injected_va: Option<Va>,

    /// Passes spent waiting for the main executable or the image list.
    capture_stalls: u32,

    /// Total gather passes executed, bounding total retries.
    gather_passes: u32,

    /// Set once every image's exports are gathered or have given up.
    gather_complete: bool,

    /// Number of observed target->system transitions (calls out of the image).
    transitions: u64,

    /// Reference instant for the per-line timestamp.
    start: Instant,

    /// macOS signatures used to render each call's arguments.
    signatures: Signatures,

    /// Coordinates typed returns, targeted runtime hooks and IPC observers.
    engine: Engine,

    /// Preserves a callback failure until the command boundary.
    error: Option<VmiError>,

    /// Bounds a passive decoder's request for a nonresident metadata page.
    decode_pagein: Option<Va>,

    /// Counts retries for the same metadata page before reporting failure.
    decode_stalls: u32,

    /// Output color scheme, disabled when stdout is not a terminal.
    palette: Palette,

    /// Set when a termination signal is received.
    terminate: Arc<AtomicBool>,
}

impl VmiHandler<MacOs<Driver>> for Tracer<'_> {
    type Output = Result<(), VmiError>;

    fn handle_event(&mut self, vmi: VmiContext<MacOs<Driver>>) -> VmiEventResponse<Arch> {
        if self.terminate.load(Ordering::Relaxed) {
            return VmiEventResponse::default().with_view(self.default);
        }
        match self.event(&vmi) {
            Ok(response) => response,
            Err(VmiError::Translation(fault)) if !is_kernel(vmi.registers().pc) => {
                if self.decode_pagein == Some(fault.va) {
                    self.decode_stalls += 1;
                }
                else {
                    self.decode_pagein = Some(fault.va);
                    self.decode_stalls = 0;
                    if let Err(err) = Self::inject_page_fault(&vmi, fault.va) {
                        self.error = Some(err);
                        self.terminate.store(true, Ordering::Relaxed);
                    }
                }
                if self.decode_stalls >= CAPTURE_STALL_LIMIT {
                    self.error = Some(VmiError::Translation(fault));
                    self.terminate.store(true, Ordering::Relaxed);
                }
                VmiEventResponse::default()
            }
            Err(err) => {
                tracing::error!(%err, "semantic trace callback failed");
                self.error = Some(err);
                self.terminate.store(true, Ordering::Relaxed);
                VmiEventResponse::default().with_view(self.default)
            }
        }
    }

    fn handle_interrupted(&mut self, _session: &VmiSession<MacOs<Driver>>) -> ControlFlow<()> {
        self.terminate.store(true, Ordering::Relaxed);
        ControlFlow::Break(())
    }

    fn cleanup(&mut self, _session: &VmiSession<MacOs<Driver>>) {
        if let Err(err) = self.stop() {
            tracing::error!(%err, "failed to restore semantic trace mappings");
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        if self.terminate.load(Ordering::Relaxed) {
            Some(match self.error.take() {
                Some(err) => Err(err),
                None => Ok(()),
            })
        }
        else {
            None
        }
    }
}

impl Drop for Tracer<'_> {
    fn drop(&mut self) {
        if !self.stop_paused
            && let Err(err) = self.stop()
        {
            tracing::error!(%err, "failed to retire exceptional trace session");
        }
        if self.stop_paused {
            if let Err(err) = self.core.reset_state() {
                tracing::error!(%err, "failed to destroy trace views");
            }
            if let Err(err) = self.core.driver().resume() {
                tracing::error!(%err, "failed to release teardown pause");
            }
            self.stop_paused = false;
        }
        tracing::info!(
            transitions = self.transitions,
            calls = self.engine.captured,
            functions = self.exports.len(),
            "trace summary"
        );
    }
}

impl<'a> Tracer<'a> {
    /// Creates a tracer bound to a target process and its translation root.
    pub fn new(
        core: &'a VmiCore<Driver>,
        system: View,
        target: View,
        identity: ProcessIdentity,
        engine: Engine,
        signatures: Signatures,
        terminate: Arc<AtomicBool>,
    ) -> Self {
        Self {
            core,
            stop_paused: false,
            default: core.default_view(),
            system,
            target,
            target_root: identity.root,
            target_pid: vmi::os::ProcessId(identity.pid),
            target_revision: 0,
            traced_range: None,
            exports: HashMap::new(),
            modules: None,
            capture_injected_va: None,
            capture_stalls: 0,
            gather_passes: 0,
            gather_complete: false,
            transitions: 0,
            start: Instant::now(),
            signatures,
            engine,
            error: None,
            decode_pagein: None,
            decode_stalls: 0,
            palette: Palette::new(stdout_supports_color()),
            terminate,
        }
    }

    /// Prevents teardown faults while mappings and pending event views are
    /// retired.
    fn stop(&mut self) -> Result<(), VmiError> {
        if !self.stop_paused {
            self.core.driver().pause()?;
            self.stop_paused = true;
        }
        self.engine
            .cleanup(self.core, self.start.elapsed().as_secs_f64(), &self.palette)?;
        for monitor in [
            EventMonitor::Register(SystemRegister::Ttbr0El1),
            EventMonitor::Breakpoint,
            EventMonitor::Singlestep,
        ] {
            self.core.monitor_disable(monitor)?;
        }
        Ok(())
    }

    /// Processes view transitions and targeted stops without guessing returns.
    fn event(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<VmiEventResponse<Arch>, VmiError> {
        let pc = vmi.registers().pc;
        let root = Pa(vmi.registers().ttbr0_el1 & TTBR_BADDR_MASK);
        let now = self.start.elapsed().as_secs_f64();
        if let Some((identity, revision)) = self.engine.primary_image() {
            if self.target_root != identity.root || self.target_revision != revision {
                self.target_root = identity.root;
                self.target_revision = revision;
                self.traced_range = None;
                self.exports.clear();
                self.modules = None;
                self.capture_injected_va = None;
                self.capture_stalls = 0;
                self.gather_passes = 0;
                self.gather_complete = false;
            }
            if !self.gather_complete && root == self.target_root && !is_kernel(pc) {
                self.advance_gather(vmi, pc);
            }
            if let Some(range) = self.traced_range {
                self.engine.main_range(vmi, self.target_root, range)?;
            }
        }
        self.engine.before_event(vmi, now, &self.palette)?;
        match vmi.event().reason() {
            EventReason::WriteSystemRegister(write) => {
                let root = Pa(write.new_value & TTBR_BADDR_MASK);
                Ok(VmiEventResponse::default().with_view(self.engine.scheduled_view(root)))
            }
            EventReason::MemoryAccess(access) => {
                if let Some(response) = self.engine.memory(vmi)? {
                    return Ok(response);
                }
                let gfn = Arch::gfn_from_pa(access.pa);
                self.engine.returned(vmi, now, &self.palette)?;
                if self.engine.traced(root, pc) {
                    self.engine
                        .entry(vmi, now, &self.palette, &self.signatures)?;
                    let access = self.engine.library_page(self.target, gfn);
                    vmi.set_memory_access(gfn, self.target, access)?;
                    vmi.set_memory_access(gfn, self.system, MemoryAccess::RW)?;
                    Ok(VmiEventResponse::default().with_view(self.target))
                }
                else {
                    if root == self.target_root && vmi.event().view() == Some(self.target) {
                        self.transitions += 1;
                    }
                    if !is_kernel(pc)
                        && vmi.event().view() == Some(self.target)
                        && let Some(export) = self.exports.get(&pc)
                        && (!IGNORED_MODULES.contains(&export.module.as_str())
                            || SEMANTIC.contains(&export.function.as_str()))
                    {
                        self.engine.call(
                            vmi,
                            &export.function,
                            &self.signatures,
                            now,
                            &self.palette,
                        )?;
                    }
                    let access = self.engine.library_page(self.system, gfn);
                    vmi.set_memory_access(gfn, self.system, access)?;
                    vmi.set_memory_access(gfn, self.target, MemoryAccess::RW)?;
                    Ok(VmiEventResponse::default().with_view(self.engine.scheduled_view(root)))
                }
            }
            EventReason::Interrupt(interrupt) => {
                if interrupt.interrupt.esr & 0xffff != 0 {
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                let original = vmi
                    .core()
                    .read_u32(Arch::pa_in_gfn(interrupt.gfn, Va(pc)))?;
                if original & 0xffe0_001f == 0xd420_0000 {
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                self.engine.returned(vmi, now, &self.palette)?;
                self.engine
                    .entry(vmi, now, &self.palette, &self.signatures)?;
                Ok(VmiEventResponse::singlestep().with_view(self.default))
            }
            EventReason::Singlestep(_) => self.engine.singlestep(vmi),
        }
    }

    /// Requests a page-in of `va` by injecting a translation fault into the
    /// vCPU that raised the current event.
    fn inject_page_fault(vmi: &VmiContext<MacOs<Driver>>, va: Va) -> Result<(), VmiError> {
        tracing::debug!(%va, "requesting page-in");
        vmi.core()
            .inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(va.0))
    }

    /// Advances the export gather on a fault at the user-mode `pc`.
    ///
    /// The gather runs in three steps, each retried on later faults until it
    /// succeeds:
    ///
    /// 1. Read the range of the main executable's `__TEXT` segment, which
    ///    the kernel maps at exec, before dyld runs.
    /// 2. Once the main executable runs, capture the dyld image list. dyld
    ///    has loaded every launch-time image by then, whereas a capture
    ///    while dyld is still loading sees a partial list.
    /// 3. Read the exports of every image into the export map.
    ///
    /// The image list, Mach-O headers and export tries live in the target's
    /// address space, and pages of the dyld shared cache are mapped into it
    /// lazily, so a read may hit a non-resident page. A translation fault
    /// triggers a page-fault injection at the missing VA so the guest pages
    /// it in, and the step continues on a later fault.
    ///
    /// Must be called only at a user-mode PC, so the injected abort is
    /// delivered in the target's EL0 context.
    fn advance_gather(&mut self, vmi: &VmiContext<MacOs<Driver>>, pc: u64) {
        // Injected page-ins and the guest's own paging change the target's
        // translation tables between passes.
        vmi.flush_v2p_cache();

        self.gather_passes += 1;
        if self.gather_passes >= MAX_GATHER_PASSES {
            self.gather_complete = true;
            tracing::warn!(
                functions = self.exports.len(),
                "gather pass budget exhausted; tracing with a partial export map"
            );
            return;
        }

        let (lo, hi) = match self.traced_range {
            Some(traced_range) => traced_range,
            None => {
                let result = self.main_text(vmi);
                match self.capture_step(vmi, result) {
                    Some((lo, hi)) => {
                        tracing::info!(text = %Va(lo), size = hi - lo, "found the main executable");
                        self.traced_range = Some((lo, hi));
                        (lo, hi)
                    }
                    None => return,
                }
            }
        };

        if self.modules.is_none() {
            if pc < lo || pc >= hi {
                return;
            }

            let result = self.capture_modules(vmi);
            match self.capture_step(vmi, result) {
                Some(modules) => {
                    tracing::info!(images = modules.len(), "captured the dyld image list");
                    self.modules = Some(modules);
                }
                None => return,
            }
        }

        self.gather_exports(vmi);
    }

    /// Unwraps the result of a capture step, or requests a page-in and
    /// schedules a retry. `Ok(None)` means the data is not there yet.
    fn capture_step<T>(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        result: Result<Option<T>, VmiError>,
    ) -> Option<T> {
        let va = match result {
            Ok(Some(value)) => {
                self.capture_injected_va = None;
                self.capture_stalls = 0;
                return Some(value);
            }
            Ok(None) => None,
            Err(VmiError::Translation(fault)) => Some(fault.va),
            Err(err) => {
                tracing::error!(%err, "failed to read the target's images; tracing disabled");
                self.gather_complete = true;
                return None;
            }
        };

        // A page is not resident in the target's address space. Page it in
        // and retry on a later fault rather than disabling tracing outright.
        if let Some(va) = va
            && self.capture_injected_va != Some(va)
        {
            self.capture_injected_va = Some(va);
            self.capture_stalls = 0;
            if let Err(err) = Self::inject_page_fault(vmi, va) {
                tracing::error!(%err, %va, "page-fault injection failed; tracing disabled");
                self.gather_complete = true;
            }
            return None;
        }

        self.capture_stalls += 1;
        if self.capture_stalls >= CAPTURE_STALL_LIMIT {
            tracing::error!(
                va = ?self.capture_injected_va,
                "the target's images never became readable; tracing disabled"
            );
            self.gather_complete = true;
        }

        None
    }

    /// Reads the exports of the pending images until every image is done or
    /// one needs a page-in.
    fn gather_exports(&mut self, vmi: &VmiContext<MacOs<Driver>>) {
        let modules = match &mut self.modules {
            Some(modules) => modules,
            None => return,
        };

        while let Some(module) = modules
            .iter_mut()
            .find(|module| module.note.is_none() && (!module.done || !module.locals_done))
        {
            let image = MacOsImage::new(vmi.state(), module.base, self.target_root);
            let result = if module.done {
                image.symbols().map(|symbols| {
                    for symbol in symbols {
                        let name = match symbol.name.strip_prefix('_') {
                            Some(name) => name,
                            None => symbol.name.as_str(),
                        };
                        self.engine
                            .configure_symbol(&module.name, name, symbol.address.0);
                    }
                    module.locals_done = true;
                })
            }
            else {
                image.exports().map(|symbols| {
                    for symbol in symbols {
                        let function = match symbol.name.strip_prefix('_') {
                            Some(function) => function.to_string(),
                            None => symbol.name,
                        };
                        self.engine
                            .configure_symbol(&module.name, &function, symbol.address.0);
                        self.exports.entry(symbol.address.0).or_insert(Export {
                            module: module.name.clone(),
                            function,
                        });
                    }
                    module.done = true;
                })
            };
            match result {
                Ok(()) => {
                    module.injected_va = None;
                    module.stalls = 0;
                }
                Err(VmiError::Translation(fault)) => {
                    let va = fault.va;
                    if module.injected_va == Some(va) {
                        // Page-in already requested for this VA; wait for it.
                        module.stalls += 1;
                        if module.stalls >= PAGEIN_STALL_LIMIT {
                            module.note = Some("paged out (page-in stalled)");
                        }
                    }
                    else {
                        module.injected_va = Some(va);
                        module.stalls = 0;
                        if let Err(err) = Self::inject_page_fault(vmi, va) {
                            tracing::warn!(%err, %va, "page-fault injection failed");
                            module.note = Some("paged out (injection failed)");
                        }
                    }
                    return;
                }
                Err(err) => {
                    tracing::debug!(%err, module = %module.name, "symbols unreadable");
                    module.note = Some(if module.done {
                        "local symbols unreadable"
                    }
                    else {
                        "exports unreadable"
                    });
                }
            }
        }

        self.gather_complete = true;
        self.engine.symbols_ready();
        let unavailable = modules
            .iter()
            .filter(|module| module.note.is_some())
            .count();
        tracing::info!(
            functions = self.exports.len(),
            images = modules.len(),
            unavailable,
            "export map ready"
        );
        for module in modules.iter() {
            if let Some(note) = module.note {
                tracing::warn!(module = %module.name, note, "image symbols incomplete");
            }
        }
    }

    /// Returns the range of the `__TEXT` segment of the target's main
    /// executable, or `None` when the target or the segment is missing.
    fn main_text(&self, vmi: &VmiContext<MacOs<Driver>>) -> Result<Option<(u64, u64)>, VmiError> {
        let process = match self.find_target(vmi)? {
            Some(process) => process,
            None => {
                tracing::warn!(pid = %self.target_pid, "target process not found");
                return Ok(None);
            }
        };

        let base = process.image_base()?;
        Ok(MacOsImage::new(vmi.state(), base, self.target_root)
            .segments()?
            .into_iter()
            .find(|segment| segment.name == "__TEXT")
            .map(|text| (text.address.0, text.address.0.saturating_add(text.size))))
    }

    /// Captures the target process's dyld images (name, base).
    ///
    /// Returns `None` while the image list is empty or does not contain the
    /// main executable.
    fn capture_modules(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
    ) -> Result<Option<Vec<ModuleDump>>, VmiError> {
        let process = match self.find_target(vmi)? {
            Some(process) => process,
            None => return Ok(None),
        };

        let image_base = process.image_base()?;
        let mut has_main = false;
        let mut modules = Vec::new();
        let mut seen = HashSet::new();

        for module in process.user_modules()? {
            let module = module?;
            let base = module.base_address()?;
            if !seen.insert(base.0) {
                continue;
            }

            has_main |= base == image_base;
            let name = module.name()?;
            modules.push(ModuleDump {
                locals_done: !LOCAL_MODULES.contains(&name.as_str()),
                name,
                base,
                done: false,
                note: None,
                injected_va: None,
                stalls: 0,
            });
        }

        Ok(has_main.then_some(modules))
    }

    /// Finds the target process by its PID.
    fn find_target<'b>(
        &self,
        vmi: &'b VmiContext<MacOs<Driver>>,
    ) -> Result<Option<MacOsProcess<'b, Driver>>, VmiError> {
        for process in vmi.os().processes()? {
            let process = process?;
            if process.id()? == self.target_pid {
                return Ok(Some(process));
            }
        }

        Ok(None)
    }
}
