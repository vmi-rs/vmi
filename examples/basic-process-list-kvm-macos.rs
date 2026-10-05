//! This example demonstrates how to enumerate the running processes of a
//! macOS guest running inside a KVM virtual machine on an Apple silicon host.
//!
//! The guest is a QEMU `vmapple` machine. Pass the QEMU pid as the first
//! argument, or let the example scan `/proc` for a `qemu-system` process. The
//! optional second argument is the directory of the profile cache. The kernel
//! profile is built from the Kernel Debug Kit that matches the guest kernel,
//! which is downloaded into the cache on first use.
//!
//! # Possible log output
//!
//! ```text
//! INFO Kernel information version=Darwin Kernel Version 27.0.0: Tue Aug 11 21:00:07 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_VMAPPLE
//! INFO Creating VMI session
//! 0xfffffe2ea1b50640 [424] ecosystemanalyti (root @ 0x000000013063c000)
//! 0xfffffe2ea1b42320 [423] mdworker_shared (root @ 0x0000000129b64000)
//! ...
//! 0xfffffe2ea1c67190 [135] xprotectd (root @ 0x00000000d530c000)
//! 0xfffffe2ea1fa4640 [1] launchd (root @ 0x00000000a5f18000)
//! 0xfffffe2ea1fb14b0 [0] kernel_task (root @ 0x0000000074390000)
//! ```

// The KVM driver introspects arm64 guests only on aarch64 hosts. On other
// hosts, the example builds to a stub that reports this.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

use std::os::fd::AsFd;

use isr::cache::IsrCache;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::arm64::{Arm64, Granule16KVa47},
    driver::kvm::VmiKvmDriver,
    os::{VmiOsProcess as _, macos::MacOs},
};

type Arch = Arm64<Granule16KVa47>;
type Driver = VmiKvmDriver<Arch>;

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

#[cfg(target_arch = "aarch64")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let pid = match args.next() {
        Some(arg) => arg.parse::<i32>()?,
        None => find_qemu_pid().ok_or("no qemu-system process found")?,
    };
    let cache_directory = args.next().unwrap_or_else(|| String::from("cache"));

    // Duplicate QEMU's KVM fds and create the VMI driver.
    let fds = kvm::attach::from_pid(pid)?;
    let driver = Driver::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        // Pause the VM to get consistent state.
        let _pause_guard = core.pause_guard()?;

        // Get the register state for the first vCPU.
        let registers = core.registers(VcpuId(0))?;

        // On macOS, `VBAR_EL1` holds the address of the exception vectors,
        // which XNU sets during early boot and leaves unchanged. The vectors
        // live in the kernel collection, so the search walks backward from
        // them to the Mach-O header of the collection.
        //
        // Therefore, we can take an arbitrary register set at any point in
        // time (as long as the OS has booted and the page tables are set up)
        // and use them to find the kernel.
        MacOs::find_kernel(&core, &registers)?.ok_or("kernel not found")?
    };
    tracing::info!(version = %kernel_info.version, "Kernel information");

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::new(cache_directory)?;
    let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
    let session = VmiSession::new(&core, &os);

    // Pause the VM again to get consistent state.
    let paused = session.pause_guard()?;

    // Create a new `VmiState` with the boot CPU registers.
    let vmi = paused.state();

    // Get the list of processes and print them.
    for process in vmi.os().processes()? {
        let process = process?;

        println!(
            "{} [{}] {} (root @ {})",
            process.object()?,
            process.id()?,
            process.name()?,
            process.translation_root()?
        );
    }

    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("The KVM driver introspects arm64 guests only on aarch64 hosts.");
}
