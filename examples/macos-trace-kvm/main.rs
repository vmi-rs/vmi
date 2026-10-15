//! arm64 semantic call and XPC tracer for a macOS guest running in KVM.
//!
//! `TTBR0_EL1` events select main-image, library/kernel and observer views.
//! Main-image-to-library transitions provide ordinary C call coverage.
//! Selected Objective-C dispatch, mutation, XPC and kernel lifecycle sites
//! use shadow breakpoints with page-table tracking. The original view remains
//! unmodified for instruction replay and guest reads.
//!
//! C declarations come from a [`sigmd`] archive of SDK headers and frameworks.
//! Objective-C calls instead use live class/metaclass metadata and method
//! encodings, including tagged receivers, app-defined classes and super
//! dispatch. Fixed arguments follow Apple's arm64 ABI. Genuine variadic tails,
//! unavailable SIMD arguments and unsupported aggregate arguments are not
//! guessed. Floating-point-returning Objective-C methods are excluded.
//!
//! Entry snapshots and exact per-thread LR/SP continuations pair scalar,
//! pointer, object and void results before the caller resumes. Bypassed frames,
//! thread/process exit, successful exec and stop print incomplete calls instead
//! of fabricated returns. Primary exec refreshes the image catalog.
//!
//! Concrete CF, heap, mutable, tagged and NSPathStore2 string representations
//! are read without guest getters. String reads, execve argv and XPC graphs are
//! bounded. Unsupported builds, inaccessible memory and truncation stay
//! visible. Unknown objects retain their runtime class and address.
//!
//! XPC intent, exact kernel transport/delivery, decoded handlers, sync/async
//! replies, dispatch continuation handoffs and process launch/exec are separate
//! observations. With `--follow`, the receiving peers and the processes
//! launched for observed requests are traced too.
//! Neither numerical port names, payload equality, timing nor launchd ancestry
//! alone establish causality.
//!
//! Nothing is tied to one macOS build. Kernel entry points, prototypes and
//! layouts come from the KDK DWARF profile. Library entry points come from
//! the images' symbol tables, Objective-C layouts from the runtime metadata
//! and the dyld shared cache header, libdispatch layouts from its published
//! source. Private libxpc objects are not read: XPC payloads are decoded from
//! the Mach message bytes, whose wire format and headers are stable.
//!
//! Ordinary library-to-library calls and newly loaded library exports are not
//! exhaustively cataloged. Selected semantic hooks cover those boundaries.
//! Objective-C reference-counting and allocation helper noise remains filtered.
//!
//! # Usage
//!
//! ```text
//! macos-trace-kvm [--follow] TARGET [QEMU-PID] [CACHE]
//! ```
//!
//! `TARGET` is a process ID or a process name. `QEMU-PID` defaults to the
//! first running `qemu-system` process and `CACHE`, the directory of the
//! profile cache, to `cache`. Stop the tracer with Ctrl-C.
//!
//! Only the target and the images it execs are traced. `--follow` also
//! traces every process that dequeues a followed message and every child
//! launched inside an observed request handler, transitively and as whole
//! processes; their lines carry a `pid=` prefix.
//!
//! The signature database is read from `assets/metadata.bin` next to this
//! example, or from the path named by the `SIGMD_METADATA` environment
//! variable. Build it with sigmd from a macOS SDK
//! (`sigmd -c sigmd-macos.yaml build`, see the sigmd README).
//!
//! A short-lived command exits before the tracer can attach to it. Start it
//! with `spawn-suspended.c` from this directory, built in the guest with
//! `cc -o spawn-suspended spawn-suspended.c`. It stops the command right
//! after exec and prints its pid. Attach the tracer to that pid, then press
//! Enter in the guest to run the command:
//!
//! ```text
//! guest$ ./spawn-suspended ls -als
//! pid 3906 suspended; attach the tracer, then press Enter
//! host#  macos-trace-kvm 3906
//! ```
//!
//! # Observed output
//!
//! Selected lines from the controlled runtime workload:
//!
//! ```text
//! [0003.841] +[OrchardProbe new] returned OrchardProbe<0x100e4a270>
//! [0003.842] -[OrchardProbe<0x100e4a270> roundTrip:-41] returned -42
//! [0003.845] -[OrchardProbe<0x100e4a270> roundTrip:-41] returned 59
//! [0003.851] ipc #24 serialize-intent pid=721 object=0x100e510b0 payload={"handle": 0, "flags": 0, "name": "org.orchard.semantic-smoke", "type": 7, "lookup-handle": 0}
//! [0003.870] ipc process-created parent-pid=700 child-pid=725 thread=0x17ec request=Some(29) relationship=observed-handler-delegated-launch
//! [0003.874] ipc process-exec pid=725 path="/bin/echo" request=Some(29) relationship=observed-launch-lineage
//! ```

mod calls;
mod encoding;
mod engine;
mod ipc;
mod objc;
mod signatures;
mod style;
mod taps;
mod tracer;
mod values;

use std::{
    os::fd::AsFd,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use isr::{Profile, cache::IsrCache};
use vmi::{
    Architecture as _, MemoryAccess, VcpuId, VmiCore, VmiError, VmiSession,
    arch::arm64::{Arm64, EventMonitor, Granule16KVa47, SystemRegister},
    driver::kvm::VmiKvmDriver,
    os::{
        VmiOsProcess as _,
        macos::{MacOs, MacOsExt as _},
    },
};

use crate::{
    engine::{Engine, ForkArguments, Lifecycle},
    ipc::{KernelLayout, ProcessIdentity, argument, enumerator},
    signatures::Signatures,
    taps::TapKind,
    tracer::Tracer,
};

/// Selects the 16KB translation geometry used by macOS guests.
type Arch = Arm64<Granule16KVa47>;

/// KVM driver specialized for the macOS guest architecture.
type Driver = VmiKvmDriver<Arch>;

/// TTBR*_EL1.BADDR mask (bits [47:1]); bit 0 is CnP and bits [63:48] hold
/// the ASID.
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFE;

/// Scans `/proc` for the first running `qemu-system` process and returns
/// its pid.
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

/// Locates the kernel lifecycle routines and their `proc` arguments by name
/// in the kernel profile.
fn lifecycle(
    profile: &Profile<'_>,
    mut relocate: impl FnMut(u64) -> Result<u64, VmiError>,
) -> Result<Lifecycle, Error> {
    let mut lifecycle = Lifecycle::default();
    let mut locate = |name: &str| -> Result<(u64, Option<isr::Function<'_>>), Error> {
        let address = profile
            .find_symbol(name)
            .with_context(|| format!("missing kernel symbol {name}"))?;
        Ok((relocate(address)?, profile.find_function(name)))
    };
    let parameter = |function: Option<isr::Function<'_>>, routine: &str, name: &str| {
        function
            .and_then(|function| argument(profile, function, name))
            .with_context(|| format!("kernel {routine} has no register parameter {name}"))
    };

    let (address, function) = locate("cloneproc")?;
    lifecycle.fork = Some(ForkArguments {
        parent: parameter(function, "cloneproc", "parent_proc")?,
        flags: parameter(function, "cloneproc", "clone_flags")?,
        exec: enumerator(profile, "cloneproc_flags_t", "CLONEPROC_EXEC")
            .map_err(|missing| anyhow::anyhow!("kernel profile lacks {missing}"))?,
    });
    lifecycle.taps.push((address, TapKind::Fork));

    let (address, function) = locate("mac_proc_notify_exec_complete")?;
    lifecycle.exec_process = parameter(function, "mac_proc_notify_exec_complete", "proc")?;
    lifecycle.taps.push((address, TapKind::Exec));

    let (address, function) = locate("mac_proc_notify_exit")?;
    lifecycle.exit_process = parameter(function, "mac_proc_notify_exit", "proc")?;
    lifecycle.taps.push((address, TapKind::Exit));

    let (address, _) = locate("thread_terminate_self")?;
    lifecycle.taps.push((address, TapKind::ThreadExit));

    Ok(lifecycle)
}

/// Attaches to the guest, resolves the target process and runs the
/// tracer until SIGINT or SIGTERM.
fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let follow = match args.iter().position(|arg| arg == "--follow") {
        Some(index) => {
            args.remove(index);
            true
        }
        None => false,
    };
    let mut args = args.into_iter();
    let target = match args.next() {
        Some(target) if target != "--help" => target,
        _ => {
            println!("Usage: macos-trace-kvm [--follow] TARGET [QEMU-PID] [CACHE]");
            println!("TARGET is a process ID or a process name");
            println!("--follow also traces message receivers and launched children");
            return Ok(());
        }
    };
    let pid = match args.next() {
        Some(arg) => arg.parse::<i32>().context("invalid QEMU pid argument")?,
        None => find_qemu_pid().context("no qemu-system process found")?,
    };
    let cache = args.next().unwrap_or_else(|| String::from("cache"));
    if args.next().is_some() {
        anyhow::bail!("too many arguments");
    }

    if kvm::host_page_size() as u64 != Arch::PAGE_SIZE {
        anyhow::bail!("this example requires matching 16K host and guest pages");
    }

    let signatures = Signatures::load().context("loading sigmd signature database")?;

    tracing::info!(pid, "setting up VMI");
    let fds = kvm::attach::from_pid(pid)?;
    let driver = Driver::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        MacOs::find_kernel(&core, &registers)?.context("kernel not found")?
    };

    tracing::info!(version = %kernel_info.version, "loading kernel profile");
    let isr = IsrCache::new(cache)?;
    let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
    let profile = entry.profile()?;

    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate.clone())?;

    let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
    let session = VmiSession::new(&core, &os);

    // Resolve the target process and its translation root.
    let identity = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();
        let pid = target.parse::<u32>().ok();
        let mut found = None;
        for process in vmi.os().processes()? {
            let process = process?;
            let matches = match pid {
                Some(pid) => process.id()?.0 == pid,
                None => process.name()? == target || process.full_name()? == target,
            };
            if matches {
                found = Some(ProcessIdentity {
                    task: process.task()?.context("target has no live task")?.0,
                    pid: process.id()?.0,
                    root: process.translation_root()?,
                });
                break;
            }
        }
        found.with_context(|| format!("{target} is not running"))?
    };
    tracing::info!(pid = identity.pid, root = %identity.root, "tracing process");
    let (kernel, lifecycle) = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();
        let relocate = |address: u64| -> Result<u64, VmiError> {
            Ok(vmi.os().relocate_kernel_address(address)?.0)
        };
        let (kernel, lines) = KernelLayout::from_profile(&profile, relocate)?;
        for line in lines {
            tracing::warn!("{line}");
        }
        (kernel, lifecycle(&profile, relocate)?)
    };

    let trace_core = &core;
    let result = session.handle(move |session| {
        let system = session.create_view(MemoryAccess::RW)?;
        let target = session.create_view(MemoryAccess::RW)?;
        let observer = session.create_view(MemoryAccess::RWX)?;
        session.monitor_enable(EventMonitor::Breakpoint)?;
        session.monitor_enable(EventMonitor::Singlestep)?;
        session.switch_to_view(observer)?;
        session.monitor_enable(EventMonitor::Register(SystemRegister::Ttbr0El1))?;
        tracing::info!(?system, ?target, "views created; monitoring TTBR0_EL1");
        let engine = Engine::new(
            system, target, observer, identity, kernel, lifecycle, follow,
        );
        Ok(Tracer::new(
            trace_core,
            system,
            target,
            identity,
            engine,
            signatures,
            terminate.clone(),
        ))
    })?;
    if let Some(result) = result {
        result?;
    }

    Ok(())
}
