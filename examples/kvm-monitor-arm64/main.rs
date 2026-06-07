//! Minimal arm64 VMI process monitor for a Windows-on-ARM guest in KVM.
//!
//! Hooks `nt!PspInsertProcess` through the `define_modules!` /
//! `define_events!` reactor and logs, for each newly created process, its id,
//! EPROCESS object, parent id, and the image path and command line read from
//! its PEB.
//!
//! The kernel is located via `VBAR_EL1` (set at boot, stable afterwards).
//! Breakpoints are kept execute-only for stealth by default. Set
//! `VMI_NO_STEALTH=1` for an RWX-safe bring-up run.
//!
//! # Usage
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc` for a
//! `qemu-system` process.
//!
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows utils-arm64" --example kvm-monitor-arm64 -- <qemu pid>
//! ```

#![expect(non_snake_case)]

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    Va, VcpuId, VmiContext, VmiCore, VmiError, VmiOs, VmiRead, VmiSession,
    arch::arm64::Arm64,
    driver::kvm::VmiKvmDriver,
    os::{
        ProcessObject, VmiOsProcess as _,
        windows::{ArchAdapter, WindowsOs},
    },
    utils::{
        reactor::{Action, ReactorHandler, define_events, define_modules},
        reactor_arm64::ReactorArm64,
    },
};

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

define_modules! {
    /// Modules used by the monitor. Only kernel symbols are hooked, so the
    /// enum is empty and the kernel is supplied through `with_kernel`.
    #[os(
        <Driver: VmiRead> WindowsOs<Driver>
        where Driver::Architecture: ArchAdapter<Driver>
    )]
    enum Module {}

    #[resolver]
    struct ModuleResolver;

    #[cache]
    struct SymbolCache;
}

define_events! {
    /// Events monitored by the process monitor.
    enum Event in Module {
        /// `nt!PspInsertProcess`
        PspInsertProcess,
    }
}

/// Reactor handler that logs process creation.
#[derive(Default)]
struct Monitor {
    /// Number of `PspInsertProcess` hits.
    PspInsertProcess_counter: u64,
}

impl Monitor {
    #[tracing::instrument(skip_all)]
    fn PspInsertProcess<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        //
        // NTSTATUS
        // PspInsertProcess (
        //     _In_ PEPROCESS NewProcess,
        //     _In_ PEPROCESS Parent,
        //     _In_ ULONG DesiredAccess,
        //     _In_ ULONG CreateFlags,
        //     ...
        //     );
        //

        self.PspInsertProcess_counter += 1;

        let NewProcess = vmi.os().function_argument(0)?;
        let Parent = vmi.os().function_argument(1)?;

        let process = vmi.os().process(ProcessObject(Va(NewProcess)))?;
        let parent = vmi.os().process(ProcessObject(Va(Parent)))?;

        let process_id = process.id()?;
        let parent_id = parent.id()?;
        let object = process.object()?;

        // The image path and command line live in the new process's PEB
        // (RTL_USER_PROCESS_PARAMETERS), read through its own address space.
        // The PEB can be absent (minimal or system processes) or not yet
        // populated this early in creation, so an unreadable value is logged
        // as empty.
        let (image_path_name, command_line) = match process.peb()? {
            Some(peb) => (
                peb.image_path_name().unwrap_or_default(),
                peb.command_line().unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };

        tracing::info!(
            %process_id,
            %parent_id,
            %object,
            image_path_name,
            command_line,
            "PspInsertProcess"
        );

        Ok(Action::default())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        tracing::info!(
            PspInsertProcess = self.PspInsertProcess_counter,
            "hit counts"
        );
    }
}

impl<Driver> ReactorHandler<WindowsOs<Driver>> for Monitor
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Output = ();
    type Event = Event;

    fn handle_event(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
        event: Self::Event,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture, Self::Output>, VmiError> {
        match event {
            Self::Event::PspInsertProcess => self.PspInsertProcess(vmi),
        }
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

    // Find the kernel so the profile can be loaded.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the kernel profile (offsets to functions and structures).
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Arm64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    let handler = Monitor::default();

    // Resolve the kernel module and collect the PspInsertProcess event.
    let mut cache = SymbolCache::default();
    let modules = ModuleResolver::default()
        .with_kernel(kernel_info.base_address, profile)
        .resolve(&session, &isr, &mut cache)?;

    let events = modules.into_events()?;

    // Stealth (execute-only) by default. VMI_NO_STEALTH=1 selects the
    // RWX-safe bring-up path. PspInsertProcess is process-creation-rate, so it
    // cannot storm the agent either way.
    let stealth = std::env::var_os("VMI_NO_STEALTH").is_none();

    session.handle(|session| {
        let reactor = if stealth {
            ReactorArm64::new(session, handler, &events)?
        }
        else {
            ReactorArm64::new_without_stealth(session, handler, &events)?
        };
        Ok(reactor.with_termination_flag(terminate_flag))
    })?;

    Ok(())
}
