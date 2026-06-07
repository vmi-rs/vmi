//! Demonstrates the arm64 VMI reactor on a Windows-on-ARM guest running in
//! KVM, monitoring the same surface as the amd64 `kvm-windows-reactor`
//! example via the `define_modules!` / `define_events!` macros:
//!
//! - `nt!NtWriteFile`: logs the full path of files being written.
//! - `netio.sys!KfdClassify`: logs network connections and their pid.
//! - `netio.sys!KfdIsLayerEmpty`: forced to return FALSE for the ALE
//!   auth/flow layers so `KfdClassify` is reached even with no active WFP
//!   filter.
//! - `ncrypt.dll!SslGenerateSessionKeys` in `lsass.exe`: logs SSL/TLS
//!   session keys. This user-mode target exercises the page-table monitor:
//!   its breakpoint is (de)activated as its page pages in and out.
//!
//! The kernel is located via `VBAR_EL1` (set at boot, stable afterwards).
//! The reactor keeps each breakpoint page execute-only for stealth and, on
//! this 16K host, marks the fused neighbor guest pages for in-kernel
//! auto-step so a hot target does not storm the agent. Set
//! `VMI_NO_STEALTH=1` for an RWX-safe bring-up run (no stealth, so no
//! mem-access storm).
//!
//! # Usage
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc` for a
//! `qemu-system` process.
//!
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows utils-arm64" --example kvm-windows-reactor-arm64 -- <qemu pid>
//! ```

#![expect(non_snake_case)]

mod ncrypt;
mod netio;
mod ntoskrnl;

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiContext, VmiCore, VmiError, VmiOs, VmiRead, VmiSession,
    arch::arm64::Arm64,
    driver::kvm::VmiKvmDriver,
    os::{
        VmiOsProcess as _,
        windows::{ArchAdapter, WindowsOs, WindowsProcess},
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

fn match_lsass<Driver>(process: &WindowsProcess<Driver>) -> Result<bool, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    // Match "lsass.exe" in SessionId 0.
    Ok(
        matches!(process.session()?, Some(session) if session.id()? == 0)
            && process.name()?.eq_ignore_ascii_case("lsass.exe"),
    )
}

define_modules! {
    /// Modules used by the reactor.
    #[os(
        <Driver: VmiRead> WindowsOs<Driver>
        where Driver::Architecture: ArchAdapter<Driver>
    )]
    enum Module {
        /// `netio.sys`
        #[module(name = "netio.sys")]
        NetioSys,

        /// `ncrypt.dll` in `lsass.exe`.
        // Note that `.., process = "lsass.exe"` would also work, but this
        // demonstrates how to use a custom predicate.
        #[module(name = "ncrypt.dll", mode(user, process = match_lsass))]
        NcryptDll,
    }

    #[resolver]
    struct ModuleResolver;

    #[cache]
    struct SymbolCache;
}

define_events! {
    /// Events monitored by the reactor.
    enum Event in Module {
        /// `nt!NtWriteFile`
        NtWriteFile,

        /// `nt!KeBugCheckEx` (diagnostic: catches a guest bugcheck).
        KeBugCheckEx,

        // `netio.sys`
        NetioSys {
            /// `netio.sys!KfdClassify`
            KfdClassify,

            /// `netio.sys!KfdIsLayerEmpty`
            KfdIsLayerEmpty,
        },

        // `ncrypt.dll`
        NcryptDll {
            /// `ncrypt.dll!SslGenerateSessionKeys`
            SslGenerateSessionKeys,
        },
    }
}

#[derive(Default)]
struct NetIo {
    NtWriteFile_counter: u64,
    KeBugCheckEx_counter: u64,
    KfdClassify_counter: u64,
    KfdIsLayerEmpty_counter: u64,
    SslGenerateSessionKeys_counter: u64,
}

impl NetIo {
    #[tracing::instrument(skip_all)]
    fn NtWriteFile<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.NtWriteFile_counter += 1;
        ntoskrnl::NtWriteFile(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn KeBugCheckEx<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.KeBugCheckEx_counter += 1;
        ntoskrnl::KeBugCheckEx(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn KfdClassify<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.KfdClassify_counter += 1;
        netio::KfdClassify(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn KfdIsLayerEmpty<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.KfdIsLayerEmpty_counter += 1;
        netio::KfdIsLayerEmpty(vmi)
    }

    #[tracing::instrument(skip_all)]
    fn SslGenerateSessionKeys<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.SslGenerateSessionKeys_counter += 1;
        ncrypt::SslGenerateSessionKeys(vmi)
    }
}

impl Drop for NetIo {
    fn drop(&mut self) {
        tracing::info!(
            NtWriteFile = self.NtWriteFile_counter,
            KeBugCheckEx = self.KeBugCheckEx_counter,
            KfdClassify = self.KfdClassify_counter,
            KfdIsLayerEmpty = self.KfdIsLayerEmpty_counter,
            SslGenerateSessionKeys = self.SslGenerateSessionKeys_counter,
            "hit counts"
        );
    }
}

impl<Driver> ReactorHandler<WindowsOs<Driver>> for NetIo
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
            Self::Event::NtWriteFile => self.NtWriteFile(vmi),
            Self::Event::KeBugCheckEx => self.KeBugCheckEx(vmi),
            Self::Event::KfdClassify => self.KfdClassify(vmi),
            Self::Event::KfdIsLayerEmpty => self.KfdIsLayerEmpty(vmi),
            Self::Event::SslGenerateSessionKeys => self.SslGenerateSessionKeys(vmi),
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

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
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

    let handler = NetIo::default();

    //
    // The following `let ncrypt_* = ...` lines demonstrate how to manually
    // resolve a module, load its profile (symbols) and add it to the resolver
    // via `with_module(_in_process)`.
    //
    // Note that this is not strictly necessary, as `ModuleResolver::resolve()`
    // will automatically resolve modules if they are not explicitly added.
    //
    // Manually resolving modules can be useful in cases where you want to deal
    // with the resolved information (base address, profile) in other places.
    //

    let ncrypt_resolved = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        // Calling `resolve_user_module(&vmi, &isr, "ncrypt.dll", "lsass.exe")`
        // would also work, but this demonstrates how to use a custom predicate.
        //
        // Also, `match_lsass` is more strict, because it specifically looks
        // for "lsass.exe" in SessionId 0 (therefore, avoiding potential false
        // positives or potential malicious processes).
        vmi::utils::resolver::resolve_user_module(&vmi, &isr, "ncrypt.dll", match_lsass)?
            .context("ncrypt.dll not found in lsass.exe")?
    };

    let ncrypt_process = ncrypt_resolved
        .process
        .context("resolved ncrypt.dll is not associated with a process")?;

    let ncrypt_entry = isr
        .entry_from_codeview(ncrypt_resolved.debug_signature)
        .context("cannot find symbols for ncrypt.dll")?;

    let ncrypt_profile = ncrypt_entry
        .profile()
        .context("cannot load profile for ncrypt.dll")?;

    // The `SymbolCache` holds the resolved `isr::Entry` items.
    let mut cache = SymbolCache::default();
    let modules = ModuleResolver::default()
        // `with_kernel` MUST be called if `Event` variants reference kernel
        // symbols - like `NtWriteFile` in this example.
        //
        // This is because the "kernel" module is always optional.
        .with_kernel(kernel_info.base_address, profile)
        .with_module_in_process(
            Module::NcryptDll,
            ncrypt_process,
            ncrypt_resolved.image_base,
            ncrypt_profile,
        )
        // This will automatically resolve the `netio.sys` module and load
        // its profile.
        //
        // Note that if we hadn't called `with_module_in_process` for
        // `ncrypt.dll`, it would also be automatically resolved here.
        .resolve(&session, &isr, &mut cache)?;

    // Finally, we collect the events according to the resolved information
    // and the metadata.
    //
    // For example, if some module/event is marked as `optional` and the
    // resolver fails to resolve it, then it will simply not be included
    // in the `events`.
    let mut events = modules.into_events()?;

    // Diagnostic: VMI_BUGCHECK_ONLY drops every hook except nt!KeBugCheckEx, so
    // the reactor can re-attach during the post-detach window with near-zero
    // perturbation and catch the stop code of a guest reset.
    if std::env::var_os("VMI_BUGCHECK_ONLY").is_some() {
        events.retain(|event| matches!(&event.event, Event::KeBugCheckEx));
        tracing::warn!("VMI_BUGCHECK_ONLY: monitoring only nt!KeBugCheckEx");
    }

    // Stealth (execute-only) by default; VMI_NO_STEALTH=1 selects the
    // RWX-safe bring-up path, which cannot storm but lets a PatchGuard-style
    // read see the planted bytes. On this 16K host the stealth path marks
    // the fused neighbor guest pages for in-kernel auto-step so a hot target
    // does not storm the agent.
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
