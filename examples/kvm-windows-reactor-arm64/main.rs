//! This example demonstrates how to use the `vmi_utils::reactor_arm64` module
//! to monitor a kernel syscall handler in a Windows guest running inside a KVM
//! virtual machine on an ARM64 host.
//!
//! It installs a software breakpoint on `nt!NtCreateFile` and logs the first
//! two AAPCS64 arguments (`x0`, `x1`) on every hit. Windows background activity
//! opens files constantly, so hits appear without any guest interaction.
//!
//! # Usage
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc` for a
//! `qemu-system` process. The example runs until interrupted with Ctrl-C.
//!
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows utils-arm64" --example kvm-windows-reactor-arm64 -- <qemu pid>
//! ```

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::{cache::IsrCache, macros::symbols};
use tracing_subscriber::EnvFilter;
use vmi::{
    Registers as _, VcpuId, VmiContext, VmiCore, VmiError, VmiSession,
    arch::arm64::Arm64,
    driver::{VmiFullDriver, kvm::VmiKvmDriver},
    os::windows::{ArchAdapter, WindowsOs},
    utils::reactor_arm64::{Action, BreakpointSpec, ReactorArm64, ReactorHandler},
};

symbols! {
    #[derive(Debug)]
    pub struct Symbols {
        NtCreateFile: u64,
    }
}

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

/// Logs every breakpoint hit with the first two function arguments.
struct LogHandler;

impl<Driver> ReactorHandler<Driver> for LogHandler
where
    Driver: VmiFullDriver<Architecture = Arm64>,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Output = ();

    fn handle_breakpoint(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        tag: &'static str,
    ) -> Result<Action<()>, VmiError> {
        // AAPCS64: integer arguments 0..7 live in x0..x7. `function_argument`
        // is the arm64 ArchAdapter accessor proven in Milestone 1.
        let arg0 = vmi.os().function_argument(0)?;
        let arg1 = vmi.os().function_argument(1)?;
        tracing::info!(tag, %arg0, %arg1, "breakpoint hit");
        Ok(Action::Default)
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

    // Setup VMI.
    tracing::info!(pid, "setting up VMI");

    // Duplicate QEMU's KVM fds and create the VMI driver.
    let fds = kvm::attach::from_pid(pid)?;
    let driver = VmiKvmDriver::<Arm64>::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information and capture the boot vCPU registers.
    // The registers are needed to pick the breakpoint's translation root.
    //
    // On ARM64 the kernel is located via `VBAR_EL1`, the base address of the
    // exception vector table. That register is set during boot and left
    // unchanged, so any register snapshot taken after the OS has booted works.
    let (kernel_info, registers) = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        let kernel_info =
            WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?;

        (kernel_info, registers)
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Resolve the target symbol VA and its translation root.
    //
    // Pick a resident kernel syscall handler that fires on normal activity.
    let symbols = Symbols::new(&profile)?;
    let target_va = kernel_info.base_address + symbols.NtCreateFile;

    // A kernel VA has bit 55 set, so `translation_root` selects `TTBR1_EL1`,
    // which maps the kernel in every process. That is the breakpoint's root.
    let target_root = registers.translation_root(target_va);

    let breakpoints = [BreakpointSpec {
        va: target_va,
        root: target_root,
        tag: "NtCreateFile",
    }];

    // Create the VMI session and arrange for a clean shutdown on signals.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Arm64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    // And we're ready to create the reactor!
    session.handle(|session| {
        Ok(ReactorArm64::new(session, LogHandler, &breakpoints)?
            .with_termination_flag(terminate_flag))
    })?;

    Ok(())
}
