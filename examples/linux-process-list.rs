//! This example lists the processes, threads, memory regions and kernel
//! modules of a Linux guest running inside a Xen domain.
//!
//! The output follows `ps -eLo pid,lwp,ppid,comm`, `/proc/<pid>/maps` and
//! `/proc/modules`, for a comparison with the guest's own view.
//!
//! # Usage
//!
//! ```bash
//! VMI_XEN_DOMAIN=linux-ubuntu26 cargo run --example linux-process-list \
//!     --features arch-amd64,driver-xen,os-linux -- --maps 1 --modules
//! ```
//!
//! isr finds the debug symbols of the kernel through its banner. Instead,
//! `--profile` names a profile that isr built before.

use std::path::PathBuf;

use anyhow::{Context as _, Error};
use clap::Parser;
use isr::cache::{Entry, IsrCache};
use vmi::{
    MemoryAccess, VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{
        ProcessId, VmiOsMapped as _, VmiOsModule as _, VmiOsProcess as _, VmiOsRegion as _,
        VmiOsThread as _,
        linux::{LinuxOs, LinuxOsExt as _, LinuxRegion},
    },
};

/// Command-line interface for the `linux-process-list` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Profile of the guest's kernel, used instead of the one that isr finds
    /// through the kernel banner.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// Prints the memory regions of the process with this PID.
    #[arg(long = "maps", value_name = "PID")]
    maps: Vec<u32>,

    /// Prints the kernel modules.
    #[arg(long)]
    modules: bool,
}

/// Driver of the example.
type Driver = VmiXenDriver<Amd64>;

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let driver = Driver::try_from_env()?.context("set VMI_XEN_DOMAIN to a domain name or ID")?;
    let core = VmiCore::new(driver)?;

    // Pause the VM to get consistent state.
    let _pause_guard = core.pause_guard()?;
    let registers = core.registers(VcpuId(0))?;

    // The banner names the kernel build, whose profile isr provides.
    let kernel_info =
        LinuxOs::<Driver>::find_kernel(&core, &registers)?.context("no kernel banner found")?;

    let entry = match cli.profile {
        Some(profile) => Entry::new(profile)?,
        None => IsrCache::new("cache")?.entry_from_linux_banner(&kernel_info.banner)?,
    };
    let profile = entry.profile()?;

    let os = LinuxOs::<Driver>::new(&profile)?;
    let session = VmiSession::new(&core, &os);
    let vmi = session.with_registers(&registers);

    println!("banner: {}", kernel_info.banner);
    println!("profile banner: {}", vmi.os().kernel_information_string()?);
    println!("kernel image base: {}", vmi.os().kernel_image_base()?);
    println!("KASLR offset: {:#x}", vmi.os().kaslr_offset()?);
    println!("KPTI: {}", vmi.os().kpti_enabled()?);

    let current_thread = vmi.os().current_thread()?;
    let current_process = vmi.os().current_process()?;
    println!(
        "current thread on vCPU 0: {} ({}), process {}",
        current_thread.id()?,
        current_thread.name()?,
        current_process.id()?
    );
    println!();

    // Processes and their threads, as `ps -eLo pid,lwp,ppid,comm` prints
    // them.
    println!("{:>7} {:>7} {:>7} COMMAND", "PID", "LWP", "PPID");
    for process in vmi.os().processes()? {
        let process = process?;
        let process_id = process.id()?;
        let parent_id = process.parent_id()?;

        for thread in process.threads()? {
            let thread = thread?;

            println!(
                "{:>7} {:>7} {:>7} {}",
                process_id,
                thread.id()?,
                parent_id,
                thread.name()?
            );
        }
    }

    // Memory regions, as `/proc/<pid>/maps` prints them, without the device
    // and inode columns.
    for pid in cli.maps {
        let process = vmi
            .os()
            .find_process(ProcessId(pid))?
            .with_context(|| format!("no process with PID {pid}"))?;

        println!();
        println!("regions of {} ({}):", pid, process.name()?);

        for region in process.regions()? {
            let region = region?;

            let path = match region.kind()?.into_mapped() {
                Some(file) => file.path()?.unwrap_or_default(),
                None => String::new(),
            };

            let offset = if path.is_empty() {
                0
            }
            else {
                region.pgoff()? << 12
            };

            println!(
                "{:08x}-{:08x} {} {:08x} {}",
                region.start()?.0,
                region.end()?.0,
                permissions(&region)?,
                offset,
                path
            );
        }
    }

    // Kernel modules, with the name, size and base address of
    // `/proc/modules`.
    if cli.modules {
        println!();
        println!("modules:");

        for module in vmi.os().modules()? {
            let module = module?;

            println!(
                "{} {} {}",
                module.name()?,
                module.size()?,
                module.base_address()?
            );
        }
    }

    Ok(())
}

/// Returns the permissions of a region as `/proc/<pid>/maps` shows them,
/// such as `r-xp`.
fn permissions(region: &LinuxRegion<Driver>) -> Result<String, Error> {
    let protection = region.protection()?;

    let flag = |access, letter| {
        if protection.contains(access) {
            letter
        }
        else {
            '-'
        }
    };

    let shared = if region.is_shared()? { 's' } else { 'p' };

    Ok([
        flag(MemoryAccess::R, 'r'),
        flag(MemoryAccess::W, 'w'),
        flag(MemoryAccess::X, 'x'),
        shared,
    ]
    .iter()
    .collect())
}
