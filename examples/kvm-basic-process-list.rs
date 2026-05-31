//! This example demonstrates how to enumerate the running processes of a
//! Windows guest running inside a KVM virtual machine.
//!
//! Pass the QEMU pid as `argv[1]`, or let the example scan `/proc` for a
//! `qemu-system` process.

use std::os::fd::AsFd;

use isr::cache::IsrCache;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::kvm::VmiKvmDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid = match std::env::args().nth(1) {
        Some(arg) => arg.parse::<i32>()?,
        None => find_qemu_pid().ok_or("no qemu-system process found")?,
    };

    // Duplicate QEMU's KVM fds and create the VMI driver.
    let fds = kvm::attach::from_pid(pid)?;
    let driver = VmiKvmDriver::<Amd64>::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        // Pause the VM to get consistent state.
        let _pause_guard = core.pause_guard()?;

        // Get the register state for the first vCPU.
        let registers = core.registers(VcpuId(0))?;

        // On AMD64 architecture, the kernel is usually found using the
        // `MSR_LSTAR` register, which contains the address of the system call
        // handler. This register is set by the operating system during boot
        // and is left unchanged (unless some rootkits are involved).
        //
        // Therefore, we can take an arbitrary registers at any point in time
        // (as long as the OS has booted and the page tables are set up) and
        // use them to find the kernel.
        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<VmiKvmDriver<Amd64>>::new(&profile)?;
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
