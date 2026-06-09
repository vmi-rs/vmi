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
//! Each call's arguments are then rendered from a bundled [`sigmd`] Windows API
//! signature database: the function is looked up by name, its parameters read
//! from the guest per AAPCS64, and pointers to `char *` / `wchar_t *`
//! dereferenced into strings, for example
//! `kernel32.dll!LoadLibraryExW (lpLibFileName="...", hFile=NULL, dwFlags=0x800)`.
//!
//! Exports are gathered on the fly from every loaded module's PE export
//! directory. Export pages that are paged out are faulted in on demand by
//! injecting a synchronous data abort (the AArch64 page-fault analog) at the
//! missing address and re-reading on a later fault.
//!
//! # Usage
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows" --example kvm-trace-arm64 -- [target-process] [qemu-pid]
//! ```
//!
//! `target-process` is the image name to trace, defaulting to
//! `procexp64a.exe`. `qemu-pid` defaults to the first running `qemu-system`
//! process. The `trace` script next to the crate wraps this with the right
//! build flags.
//!
//! The signature database is read from `assets/metadata.bin` next to this
//! example, or from the path named by the `SIGMD_METADATA` environment
//! variable.

mod signatures;
mod style;
mod tracer;

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    MemoryAccess, VcpuId, VmiCore, VmiSession,
    arch::arm64::{Arm64, EventMonitor, SystemRegister},
    driver::kvm::VmiKvmDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
};

use crate::{signatures::Signatures, tracer::Tracer};

/// TTBR*_EL1.BADDR mask (bits [47:1]); bit 0 is CnP. Matches
/// `directory_table_base_to_root`.
pub(crate) const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFE;

/// Target process image name (Process Explorer, ARM build).
pub(crate) const TARGET_NAME: &str = "procexp64a.exe";

/// KVM driver specialized for the arm64 architecture.
pub(crate) type Driver = VmiKvmDriver<Arm64>;

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

fn main() -> Result<(), Error> {
    let filter = EnvFilter::default().add_directive(tracing::Level::INFO.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let signatures = Signatures::load().context("loading sigmd signature database")?;

    let target_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| TARGET_NAME.to_string());

    let pid = match std::env::args().nth(2) {
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
            if process.name()?.eq_ignore_ascii_case(&target_name) {
                found = Some((process.id()?, process.translation_root()?));
                break;
            }
        }
        found.with_context(|| format!("{target_name} is not running"))?
    };
    tracing::info!(%target_pid, root = %target_root, "tracing {target_name}");

    let target_root = target_root.0 & TTBR_BADDR_MASK;

    session.handle(move |session| {
        let default = session.default_view();
        let system = session.create_view(MemoryAccess::RW)?;
        let target = session.create_view(MemoryAccess::RW)?;
        session.monitor_enable(EventMonitor::Register(SystemRegister::Ttbr0El1))?;
        tracing::info!(?system, ?target, "views created; monitoring TTBR0_EL1");
        Ok(Tracer::new(
            default,
            system,
            target,
            target_root,
            target_pid.0,
            target_name,
            signatures,
            terminate.clone(),
        ))
    })?;

    Ok(())
}
