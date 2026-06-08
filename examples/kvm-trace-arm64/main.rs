//! arm64 library-call tracer for a single process in a Windows-on-ARM guest.
//!
//! Detects when the target process (`procexp64a.exe`) is scheduled by
//! monitoring `TTBR0_EL1` writes (the arm64 CR3 analog) via
//! `KVM_VMI_EVENT_SYSREG`, then partitions execution with two RW-only views:
//! the target image's own code is executable only in the `target` view, and
//! all other code (DLLs, kernel) only in the `system` view. Each call out of
//! the target image faults into the `system` view; the faulting address is
//! resolved against the process's exports and printed as `module!function`.
//!
//! Exports are gathered on the fly from every loaded module's PE export
//! directory. Export pages that are paged out are faulted in on demand by
//! injecting a synchronous data abort (the AArch64 page-fault analog) at the
//! missing address and re-reading on a later fault.
//!
//! # Usage
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows" --example kvm-trace-arm64 -- <qemu pid>
//! ```

use std::{
    collections::HashMap,
    os::fd::AsFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    Architecture as _, MemoryAccess, Va, VcpuId, View, VmiContext, VmiCore, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
    arch::arm64::{Arm64, EventMonitor, EventReason, Interrupt, SystemRegister},
    driver::kvm::VmiKvmDriver,
    os::{VmiOsImage as _, VmiOsProcess as _, VmiOsUserModule as _, windows::WindowsOs},
};

/// TTBR*_EL1.BADDR mask (bits [47:1]); bit 0 is CnP. Matches
/// `directory_table_base_to_root`.
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFE;

/// Target process image name (Process Explorer, ARM build).
const TARGET_NAME: &str = "procexp64a.exe";

/// Passes to wait for one injected page-in before giving up on a module's
/// exports. At the observed transition rate this is a fraction of a second,
/// enough to cover a standby-list soft fault or a quick hard fault.
const PAGEIN_STALL_LIMIT: u32 = 4096;

/// Hard cap on total dump passes, guaranteeing the dump terminates even if a
/// page never faults in.
const MAX_DUMP_PASSES: u32 = 200_000;

/// KVM driver specialized for the arm64 architecture.
type Driver = VmiKvmDriver<Arm64>;

/// Scans `/proc` for the first running `qemu-system` process and returns its
/// pid.
fn find_qemu_pid() -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let pid = match entry.file_name().to_string_lossy().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim_end().starts_with("qemu-system") {
            return Some(pid);
        }
    }

    None
}

/// Returns true if `va` is a kernel (TTBR1) address.
fn is_kernel(va: u64) -> bool {
    (va >> 55) & 1 != 0
}

/// A resolved export: the module that provides it and the function name.
struct Export {
    /// Base DLL name of the providing module.
    module: String,

    /// Exported function name.
    function: String,
}

/// Per-module export-gather state accumulated across faults.
struct ModuleDump {
    /// Base DLL name, used to qualify resolved export names.
    name: String,

    /// Image base address.
    base: Va,

    /// Image size in bytes.
    size: u64,

    /// Set once the module's exports have been read into the export map.
    done: bool,

    /// Terminal note when the exports could not be read.
    note: Option<&'static str>,

    /// Last VA a page-fault was injected for, so retries inject once per page
    /// instead of hammering a page-in already in flight.
    injected_va: Option<Va>,

    /// Passes spent waiting on `injected_va` to become resident.
    stalls: u32,
}

/// Library-call tracer for one process.
struct Tracer {
    /// Unmodified RWX host mapping; selected when the target is not scheduled.
    default: View,

    /// View in which non-target (library and kernel) code is executable.
    system: View,

    /// View in which the target image's own code is executable.
    target: View,

    /// Target process translation root, masked with `TTBR_BADDR_MASK`.
    target_root: u64,

    /// Target process ID, used to locate the process for module enumeration.
    target_pid: u32,

    /// Low (inclusive) VA of the target's main image.
    image_lo: u64,

    /// High (exclusive) VA of the target's main image.
    image_hi: u64,

    /// Resolved exports across all modules, keyed by absolute VA, for fast
    /// call-target lookup.
    exports: HashMap<u64, Export>,

    /// Per-module export-gather state. `None` until the first fault captures
    /// the loaded-module list.
    modules: Option<Vec<ModuleDump>>,

    /// Total gather passes executed, bounding total retries.
    dump_passes: u32,

    /// Set once the export map is fully gathered, after which call tracing
    /// begins.
    dump_complete: bool,

    /// Number of observed target->system transitions (calls out of the image).
    transitions: u64,

    /// Set when a termination signal is received.
    terminate: Arc<AtomicBool>,
}

impl VmiHandler<WindowsOs<Driver>> for Tracer {
    type Output = ();

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Arm64> {
        match vmi.event().reason() {
            // TTBR0_EL1 write == address-space (process) switch on this vCPU.
            EventReason::WriteSystemRegister(w) => {
                let is_target = (w.new_value & TTBR_BADDR_MASK) == self.target_root;
                let view = if is_target { self.system } else { self.default };
                VmiEventResponse::default().with_view(view)
            }
            // Execute fault: only fires in the RW system/target views.
            EventReason::MemoryAccess(m) => {
                let pc = vmi.event().registers().pc;
                let cur = vmi.event().view();
                let gfn = Arm64::gfn_from_pa(m.pa);

                // Advance the background export gather only at a user-mode PC.
                // There the guest is in the target's user context (EL0), the
                // safe point for the page-fault injection: injecting a
                // synchronous abort at a kernel PC (EL1) clobbers the in-flight
                // EL1 exception-return state and wedges the guest.
                if !self.dump_complete && !is_kernel(pc) {
                    self.advance_dump(&vmi);
                }

                if self.in_target_image(pc) {
                    // The target's own code: executable in the target view,
                    // trapping (RW) in the system view. Run it in the target.
                    let _ = vmi.set_memory_access(gfn, self.target, MemoryAccess::RWX);
                    let _ = vmi.set_memory_access(gfn, self.system, MemoryAccess::RW);
                    VmiEventResponse::default().with_view(self.target)
                }
                else {
                    // Library or kernel code: executable in the system view,
                    // trapping in the target view. A fault here while in the
                    // target view is the target calling out; resolve the call
                    // target against the gathered exports.
                    let _ = vmi.set_memory_access(gfn, self.system, MemoryAccess::RWX);
                    let _ = vmi.set_memory_access(gfn, self.target, MemoryAccess::RW);
                    if cur == Some(self.target) {
                        self.transitions += 1;
                        if self.dump_complete {
                            if let Some(export) = self.exports.get(&pc) {
                                println!("{}!{}", export.module, export.function);
                            }
                        }
                    }
                    VmiEventResponse::default().with_view(self.system)
                }
            }
            _ => VmiEventResponse::default(),
        }
    }

    fn handle_interrupted(&mut self, _session: &VmiSession<WindowsOs<Driver>>) {
        self.terminate.store(true, Ordering::Relaxed);
    }

    fn poll(&self) -> Option<Self::Output> {
        self.terminate.load(Ordering::Relaxed).then_some(())
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        tracing::info!(
            transitions = self.transitions,
            functions = self.exports.len(),
            "trace summary"
        );
    }
}

impl Tracer {
    /// Returns true if `pc` falls inside the target process's main image.
    fn in_target_image(&self, pc: u64) -> bool {
        pc >= self.image_lo && pc < self.image_hi
    }

    /// Advances the background export gather by one step on a fault.
    ///
    /// The first call captures the loaded-module list and the target image
    /// range. Each call then reads the exports of the first still-pending
    /// module into the export map. A translation fault triggers a page-fault
    /// injection at the missing VA so the guest pages it in, to be re-read on
    /// a later call. When every module is resolved (or has given up), the map
    /// is marked complete and call tracing begins.
    ///
    /// Must be called only at a user-mode PC, so the injected abort is
    /// delivered in the target's EL0 context. Injecting at a kernel PC (EL1)
    /// corrupts the in-flight EL1 exception state and wedges the guest.
    fn advance_dump(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) {
        if self.modules.is_none() {
            match self.capture_modules(vmi) {
                Ok(modules) => {
                    if let Some(image) = modules
                        .iter()
                        .find(|module| module.name.eq_ignore_ascii_case(TARGET_NAME))
                    {
                        self.image_lo = image.base.0;
                        self.image_hi = image.base.0 + image.size;
                    }
                    self.modules = Some(modules);
                }
                Err(err) => {
                    tracing::error!(%err, "failed to enumerate modules; tracing disabled");
                    self.dump_complete = true;
                    return;
                }
            }
        }

        self.dump_passes += 1;
        if self.dump_passes >= MAX_DUMP_PASSES {
            self.dump_complete = true;
            tracing::warn!(
                functions = self.exports.len(),
                "gather pass budget exhausted; tracing with a partial export map"
            );
            return;
        }
        let vcpu = vmi.event().vcpu_id();

        let index = match self
            .modules
            .as_ref()
            .expect("module list captured above")
            .iter()
            .position(|module| !module.done && module.note.is_none())
        {
            Some(index) => index,
            None => {
                self.dump_complete = true;
                tracing::info!(
                    functions = self.exports.len(),
                    "export map ready; tracing calls"
                );
                return;
            }
        };
        let base = self.modules.as_ref().unwrap()[index].base;

        match vmi.os().image(base).and_then(|image| image.exports()) {
            Ok(symbols) => {
                let module = self.modules.as_ref().unwrap()[index].name.clone();
                for symbol in symbols {
                    self.exports.insert(
                        symbol.address.0,
                        Export {
                            module: module.clone(),
                            function: symbol.name,
                        },
                    );
                }
                self.modules.as_mut().unwrap()[index].done = true;
            }
            Err(VmiError::Translation(pfs)) => {
                let va = pfs[0].va;
                let module = &mut self.modules.as_mut().unwrap()[index];
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
                    if let Err(err) = vmi
                        .core()
                        .inject_interrupt(vcpu, Interrupt::page_fault(va.0))
                    {
                        tracing::warn!(%err, %va, "page-fault injection failed");
                        module.note = Some("paged out (injection failed)");
                    }
                }
            }
            Err(_) => {
                self.modules.as_mut().unwrap()[index].note = Some("exports unreadable");
            }
        }
    }

    /// Captures the target process's loaded-module list (name, base, size).
    fn capture_modules(
        &self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Vec<ModuleDump>, VmiError> {
        for process in vmi.os().processes()? {
            let process = process?;
            if process.id()?.0 != self.target_pid {
                continue;
            }

            let peb = match process.peb()? {
                Some(peb) => peb,
                None => {
                    tracing::warn!("target process has no PEB");
                    return Ok(Vec::new());
                }
            };

            let mut modules = Vec::new();
            for module in peb.ldr()?.in_load_order_modules()? {
                let module = module?;
                modules.push(ModuleDump {
                    name: module.name()?,
                    base: module.base_address()?,
                    size: module.size()?,
                    done: false,
                    note: None,
                    injected_va: None,
                    stalls: 0,
                });
            }
            return Ok(modules);
        }

        tracing::warn!(pid = self.target_pid, "target process not found");
        Ok(Vec::new())
    }
}

fn main() -> Result<(), Error> {
    let filter = EnvFilter::default().add_directive(tracing::Level::INFO.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let pid = match std::env::args().nth(1) {
        Some(arg) => arg.parse::<i32>().context("invalid QEMU pid argument")?,
        None => find_qemu_pid().context("no qemu-system process found")?,
    };

    tracing::info!(pid, "setting up VMI");
    let fds = kvm::attach::from_pid(pid)?;
    let driver = VmiKvmDriver::<Arm64>::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate.clone())?;

    let os = WindowsOs::<Driver>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    // Resolve procexp64a.exe and cache its translation root.
    let (target_pid, target_root) = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);
        let mut found = None;
        for process in vmi.os().processes()? {
            let process = process?;
            if process.name()?.eq_ignore_ascii_case(TARGET_NAME) {
                found = Some((process.id()?, process.translation_root()?));
                break;
            }
        }
        found.with_context(|| format!("{TARGET_NAME} is not running"))?
    };
    tracing::info!(%target_pid, root = %target_root, "tracing {TARGET_NAME}");

    let target_root = target_root.0 & TTBR_BADDR_MASK;

    session.handle(|session| {
        let default = session.default_view();
        let system = session.create_view(MemoryAccess::RW)?;
        let target = session.create_view(MemoryAccess::RW)?;
        session.monitor_enable(EventMonitor::Register(SystemRegister::Ttbr0El1))?;
        tracing::info!(?system, ?target, "views created; monitoring TTBR0_EL1");
        Ok(Tracer {
            default,
            system,
            target,
            target_root,
            target_pid: target_pid.0,
            image_lo: 0,
            image_hi: 0,
            exports: HashMap::new(),
            modules: None,
            dump_passes: 0,
            dump_complete: false,
            transitions: 0,
            terminate: terminate.clone(),
        })
    })?;

    Ok(())
}
