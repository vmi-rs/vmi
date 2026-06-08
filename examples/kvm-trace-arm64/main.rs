//! arm64 user/kernel execution-boundary tracer for a Windows-on-ARM guest.
//!
//! Traces every user<->kernel transition of a single process
//! (`procexp64a.exe`) using two RW-only alternate views that ping-pong on
//! execute faults. Process scheduling is detected by monitoring `TTBR0_EL1`
//! writes (the arm64 CR3 analog) via `KVM_VMI_EVENT_SYSREG`.
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
    Architecture as _, MemoryAccess, VcpuId, View, VmiContext, VmiCore, VmiEventResponse,
    VmiHandler, VmiSession,
    arch::arm64::{Arm64, EventMonitor, EventReason, SystemRegister},
    driver::kvm::VmiKvmDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
};

/// TTBR*_EL1.BADDR mask (bits [47:1]); bit 0 is CnP. Matches
/// `directory_table_base_to_root`.
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFE;

/// Target process image name (Process Explorer, ARM build).
const TARGET_NAME: &str = "procexp64a.exe";

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

    /// Number of observed user<->kernel transitions.
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
                let pc_kernel = is_kernel(pc);
                let cur = vmi.event().view();
                let gfn = Arm64::gfn_from_pa(m.pa);

                if cur == Some(self.system) {
                    if pc_kernel {
                        let _ = vmi.set_memory_access(gfn, self.system, MemoryAccess::RWX);
                        VmiEventResponse::default()
                    }
                    else {
                        self.transitions += 1;
                        tracing::info!("KERNEL->USER pc={pc:#x}");
                        VmiEventResponse::default().with_view(self.target)
                    }
                }
                else if cur == Some(self.target) {
                    if pc_kernel {
                        self.transitions += 1;
                        tracing::info!("USER->KERNEL pc={pc:#x}");
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
            transitions: 0,
            terminate: terminate.clone(),
        })
    })?;

    Ok(())
}
