use std::fs;
use std::os::fd::RawFd;

use vmi_arch_amd64::Amd64;
use vmi_core::{VcpuId, VmiCore};
use vmi_driver_kvm::VmiKvmDriver;

/// Discover QEMU process and its KVM fd layout from /proc.
///
/// Returns (pid, vm_fd, vcpu_fds).
fn find_qemu_vm() -> Result<(u32, RawFd, Vec<RawFd>), Box<dyn std::error::Error>> {
    // Find QEMU process.
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

    // Scan fds to find kvm-vm and kvm-vcpu fds.
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
            // Extract vCPU index from "anon_inode:kvm-vcpu:N".
            if let Some(idx_str) = link_str.rsplit(':').next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    vcpu_fds_nums.push((idx, fd_num));
                }
            }
        }
    }

    let vm_fd_num = vm_fd_num.ok_or("no kvm-vm fd found")?;

    // Sort vCPU fds by index.
    vcpu_fds_nums.sort_by_key(|(idx, _)| *idx);

    eprintln!(
        "VM fd: {vm_fd_num}, vCPU fds: {:?}",
        vcpu_fds_nums
            .iter()
            .map(|(idx, fd)| format!("vcpu:{idx}=fd{fd}"))
            .collect::<Vec<_>>()
    );

    // Duplicate the fds into our process using pidfd_getfd.
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

    // Close the pidfd.
    unsafe { libc::close(pidfd) };

    eprintln!(
        "Duplicated: vm_fd={vm_fd}, vcpu_fds={:?}",
        vcpu_fds
    );

    Ok((pid, vm_fd, vcpu_fds))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_pid, vm_fd, vcpu_fds) = find_qemu_vm()?;
    let num_vcpus = vcpu_fds.len() as u32;

    // Create VMI driver.
    eprintln!("Creating VMI driver...");
    let driver = VmiKvmDriver::<Amd64>::new(vm_fd, num_vcpus, vcpu_fds)?;
    eprintln!("VMI driver created successfully");
    let vmi = VmiCore::new(driver)?;

    // Pause the VM and read registers.
    // KVM_VMI_PAUSE_VM is synchronous: it returns only after all vCPUs
    // have exited guest mode, so KVM_GET_REGS will not block.
    let _pause_guard = vmi.pause_guard()?;

    let info = vmi.info()?;
    eprintln!("VM info: {} vCPUs, page_size={}", info.vcpus, info.page_size);

    for vcpu_id in 0..info.vcpus {
        let registers = vmi.registers(VcpuId(vcpu_id))?;

        println!("=== vCPU {vcpu_id} ===");
        println!("  RIP = {:#018x}", registers.rip);
        println!("  RSP = {:#018x}", registers.rsp);
        println!("  CR0 = {:#018x}", u64::from(registers.cr0));
        println!("  CR3 = {:#018x}", u64::from(registers.cr3));
        println!("  CR4 = {:#018x}", u64::from(registers.cr4));
        println!("  EFER = {:#018x}", u64::from(registers.msr_efer));
        println!(
            "  CS = {{ sel={:#06x}, base={:#018x}, limit={:#010x} }}",
            u16::from(registers.cs.selector),
            registers.cs.base,
            registers.cs.limit,
        );

        // Read IDT from guest memory.
        match Amd64::interrupt_descriptor_table(&vmi, &registers) {
            Ok(idt) => println!("  IDT: {} entries", idt.len()),
            Err(e) => eprintln!("  IDT read failed: {e}"),
        }
    }

    Ok(())
}
