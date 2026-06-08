//! arm64 module/export dumper for a single process in a Windows-on-ARM guest.
//!
//! Detects when the target process (`procexp64a.exe`) is scheduled by
//! monitoring `TTBR0_EL1` writes (the arm64 CR3 analog) via
//! `KVM_VMI_EVENT_SYSREG`, and uses two RW-only alternate views that ping-pong
//! on execute faults to catch the kernel<->user boundary. On the first
//! transition into user mode, where the target's user address space is live,
//! it enumerates every module (DLL) loaded in the process and prints each
//! module's exported symbols, then exits. Export pages that are paged out are
//! faulted in on demand by injecting a synchronous data abort (the AArch64
//! page-fault analog) at the missing address and re-reading on a later
//! transition.
//!
//! # Usage
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows" --example kvm-trace-arm64 -- <qemu pid>
//! ```

use std::{
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

/// Per-module dump state accumulated across transitions.
struct ModuleDump {
    /// Base DLL name.
    name: String,

    /// Image base address.
    base: Va,

    /// Image size in bytes.
    size: u64,

    /// Resolved exports as (address, name), once readable. `None` while still
    /// pending a page-in.
    exports: Option<Vec<(Va, String)>>,

    /// Terminal note when the exports could not be read.
    note: Option<&'static str>,

    /// Last VA a page-fault was injected for, so retries inject once per page
    /// instead of hammering a page-in already in flight.
    injected_va: Option<Va>,

    /// Passes spent waiting on `injected_va` to become resident.
    stalls: u32,

    /// Whether any page-fault injection was used to read this module.
    used_injection: bool,
}

/// User/kernel transition tracer for one process.
struct Tracer {
    /// Unmodified RWX host mapping; selected when the target is not scheduled.
    default: View,

    /// RW-only view representing kernel-side execution of the target.
    system: View,

    /// RW-only view representing user-side execution of the target.
    target: View,

    /// Target process translation root, masked with `TTBR_BADDR_MASK`.
    target_root: u64,

    /// Target process ID, used to locate the process for module enumeration.
    target_pid: u32,

    /// Number of observed user<->kernel transitions.
    transitions: u64,

    /// Per-module dump state. `None` until the first user-mode entry captures
    /// the loaded-module list.
    dump: Option<Vec<ModuleDump>>,

    /// Total dump passes executed, bounding total retries.
    dump_passes: u32,

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
                let pc_kernel = is_kernel(pc);
                let cur = vmi.event().view();
                let gfn = Arm64::gfn_from_pa(m.pa);

                if cur == Some(self.system) {
                    if pc_kernel {
                        let _ = vmi.set_memory_access(gfn, self.system, MemoryAccess::RWX);
                        VmiEventResponse::default()
                    }
                    else {
                        // Reached user mode with the target scheduled: its user
                        // address space is live, so drive the module/export dump
                        // (enumerate, then fault in and re-read paged-out export
                        // pages over later transitions). Terminates when done.
                        self.advance_dump(&vmi);
                        self.transitions += 1;
                        tracing::trace!("KERNEL->USER pc={pc:#x}");
                        VmiEventResponse::default().with_view(self.target)
                    }
                }
                else if cur == Some(self.target) {
                    if pc_kernel {
                        self.transitions += 1;
                        tracing::trace!("USER->KERNEL pc={pc:#x}");
                        VmiEventResponse::default().with_view(self.system)
                    }
                    else {
                        let _ = vmi.set_memory_access(gfn, self.target, MemoryAccess::RWX);
                        VmiEventResponse::default()
                    }
                }
                else {
                    VmiEventResponse::default()
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
        tracing::info!(transitions = self.transitions, "trace summary");
    }
}

impl Tracer {
    /// Advances the module/export dump by one step on a user-mode entry.
    ///
    /// The first call captures the loaded-module list. Each call then tries to
    /// read the exports of the first still-pending module. A translation fault
    /// triggers a page-fault injection at the missing VA so the guest pages it
    /// in, to be re-read on a later call. When every module is resolved (or has
    /// given up) it prints the dump and requests teardown.
    fn advance_dump(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) {
        if self.dump.is_none() {
            match self.capture_modules(vmi) {
                Ok(modules) => self.dump = Some(modules),
                Err(err) => {
                    tracing::error!(%err, "failed to enumerate modules");
                    self.terminate.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }

        self.dump_passes += 1;
        let give_up = self.dump_passes >= MAX_DUMP_PASSES;
        let vcpu = vmi.event().vcpu_id();
        let target_pid = self.target_pid;
        let modules = self.dump.as_mut().expect("module list captured above");

        let index = match modules
            .iter()
            .position(|module| module.exports.is_none() && module.note.is_none())
        {
            Some(index) => index,
            None => {
                print_dump(target_pid, modules);
                self.terminate.store(true, Ordering::Relaxed);
                return;
            }
        };

        let module = &mut modules[index];

        if give_up {
            module.note = Some("paged out (dump pass budget exhausted)");
            return;
        }

        match vmi
            .os()
            .image(module.base)
            .and_then(|image| image.exports())
        {
            Ok(exports) => {
                module.exports = Some(
                    exports
                        .into_iter()
                        .map(|symbol| (symbol.address, symbol.name))
                        .collect(),
                );
            }
            Err(VmiError::Translation(pfs)) => {
                let va = pfs[0].va;
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
                    module.used_injection = true;
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
                module.note = Some("exports unreadable");
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
                    exports: None,
                    note: None,
                    injected_va: None,
                    stalls: 0,
                    used_injection: false,
                });
            }
            return Ok(modules);
        }

        tracing::warn!(pid = self.target_pid, "target process not found");
        Ok(Vec::new())
    }
}

/// Prints the captured module list, each module followed by its exports.
fn print_dump(target_pid: u32, modules: &[ModuleDump]) {
    let total_modules = modules.len();
    let mut export_total = 0usize;
    let mut injected = 0usize;
    let mut unavailable = 0usize;

    println!();
    println!(
        "==== {} (pid {}) modules and exports ====",
        TARGET_NAME, target_pid
    );

    for module in modules {
        let tag = if module.used_injection {
            " [paged in via fault injection]"
        }
        else {
            ""
        };

        println!();
        println!(
            "{} @ {} (size {:#x}){}",
            module.name, module.base, module.size, tag
        );

        if let Some(exports) = &module.exports {
            for (address, name) in exports {
                println!("    {address} {name}");
            }
            export_total += exports.len();
        }

        if let Some(note) = module.note {
            println!("    <{note}>");
            unavailable += 1;
        }

        if module.used_injection {
            injected += 1;
        }
    }

    println!();
    println!(
        "==== {total_modules} modules, {export_total} exports total; \
         {injected} needed page-in, {unavailable} unavailable ===="
    );
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
            transitions: 0,
            dump: None,
            dump_passes: 0,
            terminate: terminate.clone(),
        })
    })?;

    Ok(())
}
