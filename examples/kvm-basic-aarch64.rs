use std::fs;
use std::os::fd::RawFd;

use vmi_arch_aarch64::Aarch64;
use vmi_core::{Architecture as _, Gfn, VmiCore};
use vmi_driver_kvm::VmiKvmDriver;

/// Discover QEMU process and its KVM fd layout from /proc.
///
/// Returns (pid, vm_fd, vcpu_fds).
fn find_qemu_vm() -> Result<(u32, RawFd, Vec<RawFd>), Box<dyn std::error::Error>> {
    let mut qemu_pid = None;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        let cmdline = match fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if cmdline.contains("qemu") {
            qemu_pid = Some(pid);
            break;
        }
    }

    let pid = qemu_pid.ok_or("no QEMU process found")?;
    eprintln!("Found QEMU pid: {pid}");

    let fd_dir = format!("/proc/{pid}/fd");
    let mut vm_fd_num = None;
    let mut vcpu_fds_nums: Vec<(u32, RawFd)> = Vec::new();

    for entry in fs::read_dir(&fd_dir)? {
        let entry = entry?;
        let fd_num: RawFd = match entry.file_name().to_string_lossy().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let link = match fs::read_link(entry.path()) {
            Ok(l) => l,
            Err(_) => continue,
        };

        let link_str = link.to_string_lossy();

        if link_str.contains("kvm-vm") && vm_fd_num.is_none() {
            vm_fd_num = Some(fd_num);
        } else if link_str.contains("kvm-vcpu:") && !link_str.contains("kvm-vcpu-stats") {
            if let Some(idx_str) = link_str.rsplit(':').next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    vcpu_fds_nums.push((idx, fd_num));
                }
            }
        }
    }

    let vm_fd_num = vm_fd_num.ok_or("no kvm-vm fd found")?;
    vcpu_fds_nums.sort_by_key(|(idx, _)| *idx);

    eprintln!(
        "VM fd: {vm_fd_num}, vCPU fds: {:?}",
        vcpu_fds_nums
            .iter()
            .map(|(idx, fd)| format!("vcpu:{idx}=fd{fd}"))
            .collect::<Vec<_>>()
    );

    let pidfd = unsafe {
        libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_int)
    } as RawFd;
    if pidfd < 0 {
        return Err(format!(
            "pidfd_open failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let dup_fd = |target_fd: RawFd| -> Result<RawFd, Box<dyn std::error::Error>> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_pidfd_getfd,
                pidfd as libc::c_int,
                target_fd as libc::c_int,
                0 as libc::c_uint,
            )
        } as RawFd;
        if fd < 0 {
            Err(format!(
                "pidfd_getfd(fd={target_fd}) failed: {}",
                std::io::Error::last_os_error()
            )
            .into())
        } else {
            Ok(fd)
        }
    };

    let vm_fd = dup_fd(vm_fd_num)?;
    let mut vcpu_fds = Vec::new();
    for &(_, fd_num) in &vcpu_fds_nums {
        vcpu_fds.push(dup_fd(fd_num)?);
    }

    unsafe { libc::close(pidfd) };

    eprintln!("Duplicated: vm_fd={vm_fd}, vcpu_fds={vcpu_fds:?}");

    Ok((pid, vm_fd, vcpu_fds))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_pid, vm_fd, vcpu_fds) = find_qemu_vm()?;
    let num_vcpus = vcpu_fds.len() as u32;

    // Create VMI driver.
    eprintln!("Creating VMI driver...");
    let driver = VmiKvmDriver::<Aarch64>::new(vm_fd, num_vcpus, vcpu_fds)?;
    eprintln!("VMI driver created successfully");
    let vmi = VmiCore::new(driver)?;

    // Pause the VM and read basic info.
    let _pause_guard = vmi.pause_guard()?;

    let info = vmi.info()?;
    eprintln!(
        "VM info: {} vCPUs, page_size={}",
        info.vcpus, info.page_size
    );

    // Read a page of guest physical memory and hexdump it.
    // ARM64 QEMU "virt" machine RAM starts at 0x40000000 (1 GiB).
    let gfn = Gfn(0x40000); // PA = 0x40000000
    match vmi.read_page(gfn) {
        Ok(page) => {
            let pa = Aarch64::pa_from_gfn(gfn);
            println!("=== Guest physical page at {pa} ===");
            for (i, chunk) in page.chunks(16).take(4).enumerate() {
                print!("  {:#010x}: ", pa.0 + (i * 16) as u64);
                for byte in chunk {
                    print!("{byte:02x} ");
                }
                println!();
            }
            println!("  ... ({} bytes total)", page.len());
        }
        Err(e) => eprintln!("Failed to read page at GFN {gfn}: {e}"),
    }

    Ok(())
}
