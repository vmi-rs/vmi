//! Hooks the user-mode `ntdll!NtWriteFile` on an ARM64 Windows guest and
//! resolves the file `HANDLE` argument to a path.
//!
//! Unlike the kernel hooks in `kvm-windows-reactor-arm64`, the target lives in
//! pageable user memory, so the reactor follows it with the page-table monitor:
//! the breakpoint is (de)activated as the page pages in and out. `ntdll` is a
//! shared image and the breakpoint is global, so a hook installed via one
//! reference process fires for every process that writes a file; the file
//! handle is resolved in the firing process's own context.
//!
//! # Usage
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc`. Set
//! `VMI_NO_STEALTH=1` for an RWX-safe bring-up run (no execute-only stealth, so
//! no mem-access storm). The example runs until interrupted with Ctrl-C.
//!
//! ```text
//! cargo run --features="arch-arm64 driver-kvm os-windows utils-arm64" --example kvm-windows-ntwritefile-arm64 -- <qemu pid>
//! ```

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::{cache::IsrCache, macros::symbols};
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiContext, VmiCore, VmiError, VmiSession,
    arch::arm64::Arm64,
    driver::{VmiFullDriver, kvm::VmiKvmDriver},
    os::{
        VmiOsProcess as _,
        windows::{ArchAdapter, WindowsFileObject, WindowsOs},
    },
    utils::{
        reactor_arm64::{Action, BreakpointSpec, ReactorArm64, ReactorHandler},
        resolver::resolve_user_module,
    },
};

symbols! {
    #[derive(Debug)]
    pub struct NtdllSymbols {
        NtWriteFile: u64,
    }
}

/// Reference process used to resolve and monitor ntdll. ntdll is a shared image
/// and the breakpoint is global, so this is only the install / monitor root; the
/// hook fires for every process that writes a file.
const REFERENCE_PROCESS: &str = "explorer.exe";

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

/// Logs the path behind every `NtWriteFile` file handle.
#[derive(Default)]
struct NtWrite {
    /// Number of `NtWriteFile` hits observed.
    hits: u64,
}

impl NtWrite {
    /// Resolves and logs the file handle from an `NtWriteFile` breakpoint hit.
    fn nt_write_file<Driver>(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<Action<()>, VmiError>
    where
        Driver: VmiFullDriver<Architecture = Arm64>,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.hits += 1;

        // NtWriteFile's first argument (AAPCS64 x0) is the file HANDLE.
        let handle = vmi.os().function_argument(0)?;

        // Resolve the handle in the firing process's context. It may be a
        // pseudo-handle, a non-file object, or its handle table may be paged
        // out, so any failure is expected and not fatal: fall back to the raw
        // handle value.
        let process = vmi.os().current_process()?;
        match process.lookup_object::<WindowsFileObject<_>>(handle) {
            Ok(Some(file)) => match file.full_path() {
                Ok(path) => tracing::info!(%path, count = self.hits, "NtWriteFile"),
                Err(err) => tracing::info!(
                    handle = format_args!("{handle:#x}"),
                    %err,
                    count = self.hits,
                    "NtWriteFile (path unreadable)"
                ),
            },
            Ok(None) => tracing::info!(
                handle = format_args!("{handle:#x}"),
                count = self.hits,
                "NtWriteFile (not a file handle)"
            ),
            Err(err) => tracing::info!(
                handle = format_args!("{handle:#x}"),
                %err,
                count = self.hits,
                "NtWriteFile (handle unresolved)"
            ),
        }

        Ok(Action::Default)
    }
}

impl<Driver> ReactorHandler<Driver> for NtWrite
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
        match tag {
            "NtWriteFile" => self.nt_write_file(vmi),
            tag => {
                tracing::warn!(tag, "unexpected breakpoint tag");
                Ok(Action::Default)
            }
        }
    }
}

impl Drop for NtWrite {
    fn drop(&mut self) {
        tracing::info!(hits = self.hits, "ntwritefile reactor summary");
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

    // Locate the kernel via VBAR_EL1 (set at boot, stable afterwards).
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Arm64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    // Resolve ntdll!NtWriteFile in the reference process and pick its user
    // translation root (TTBR0).
    let (ntwritefile_va, root) = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        let resolved = resolve_user_module(&vmi, &isr, "ntdll.dll", REFERENCE_PROCESS)?
            .context("ntdll.dll not found in reference process")?;
        let process = resolved
            .process
            .context("ntdll resolution returned no process")?;
        let root = vmi.os().process(process)?.translation_root()?;

        let ntdll_entry = isr
            .entry_from_codeview(resolved.debug_signature)
            .context("cannot find symbols for ntdll.dll")?;
        let ntdll_profile = ntdll_entry
            .profile()
            .context("cannot load profile for ntdll.dll")?;
        let ntdll_symbols = NtdllSymbols::new(&ntdll_profile)?;

        (resolved.image_base + ntdll_symbols.NtWriteFile, root)
    };

    let breakpoints = [BreakpointSpec {
        va: ntwritefile_va,
        root,
        tag: "NtWriteFile",
    }];

    // Stealth (execute-only) by default; VMI_NO_STEALTH=1 selects the RWX-safe
    // bring-up path, which cannot storm but lets a PatchGuard-style read see the
    // planted bytes.
    let stealth = std::env::var_os("VMI_NO_STEALTH").is_none();

    session.handle(|session| {
        let reactor = if stealth {
            ReactorArm64::new(session, NtWrite::default(), &breakpoints)?
        }
        else {
            ReactorArm64::new_without_stealth(session, NtWrite::default(), &breakpoints)?
        };
        Ok(reactor.with_termination_flag(terminate_flag))
    })?;

    Ok(())
}
