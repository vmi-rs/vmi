//! # [`recipe!`] example (KVM)
//!
//! This example demonstrates how to write a simple recipe using the KVM driver.
//!
//! The recipe is injected into the `explorer.exe` process and shows
//! a message box.
//!
//! # Usage
//!
//! ```text
//! cargo run --example kvm-windows-recipe-messagebox [-- <qemu-pid>]
//! ```
//!
//! # Possible log output
//!
//! ```text
//! Found QEMU pid: 12345
//! Creating VMI driver...
//! Kernel found at base 0xfffff80002861000
//!  INFO Creating VMI session
//!  INFO found explorer.exe pid=1248 object=0xfffffa80030e9060
//! DEBUG injector{vcpu=2 rip=0x0000000077c618ca}:memory_access: thread hijacked current_tid=1488
//! DEBUG injector{vcpu=2 rip=0x0000000077c618ca}:memory_access: recipe step index=0
//! DEBUG injector{vcpu=1 rip=0x0000000077c618ca}:memory_access: recipe finished result=0x0000000000000001
//! ```

use std::fs;
use std::os::fd::RawFd;

use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::VmiFullDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
    utils::injector::{Recipe, UserInjectorHandler, recipe},
};
use vmi_driver_kvm::VmiKvmDriver;

/// Discover QEMU process and duplicate its KVM fds into our process.
fn find_qemu_vm(
    target_pid: Option<u32>,
) -> Result<(u32, RawFd, Vec<RawFd>), Box<dyn std::error::Error>> {
    let pid = if let Some(pid) = target_pid {
        pid
    } else {
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
        qemu_pid.ok_or("no QEMU process found")?
    };

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

    unsafe { libc::close(pidfd) };

    eprintln!("Duplicated: vm_fd={vm_fd}, vcpu_fds={vcpu_fds:?}");

    Ok((pid, vm_fd, vcpu_fds))
}

struct MessageBox {
    caption: String,
    text: String,
}

impl MessageBox {
    pub fn new(caption: impl AsRef<str>, text: impl AsRef<str>) -> Self {
        Self {
            caption: caption.as_ref().to_string(),
            text: text.as_ref().to_string(),
        }
    }
}

#[rustfmt::skip]
fn recipe_factory<Driver>(data: MessageBox) -> Recipe<WindowsOs<Driver>, MessageBox>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    recipe![
        Recipe::<WindowsOs<Driver>, _>::new(data),
        {
            inject! {
                user32!MessageBoxA(
                    0,                          // hWnd
                    data![text],                // lpText
                    data![caption],             // lpCaption
                    0                           // uType
                )
            }
        }
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .init();

    let target_pid = std::env::args()
        .nth(1)
        .map(|s| s.parse::<u32>().expect("invalid PID"));

    let (_pid, vm_fd, vcpu_fds) = find_qemu_vm(target_pid)?;
    let num_vcpus = vcpu_fds.len() as u32;

    // Create VMI driver.
    eprintln!("Creating VMI driver...");
    let driver = VmiKvmDriver::<Amd64>::new(vm_fd, num_vcpus, vcpu_fds)?;
    let core = VmiCore::new(driver)?;

    // Find the Windows kernel.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        eprintln!("Finding Windows kernel...");
        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    eprintln!(
        "Kernel found at base {:#x}, CodeView: {:?}",
        kernel_info.base_address, kernel_info.codeview
    );

    // Load the profile from ISR cache.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;

    // Leak the entry and profile so they live for 'static.
    let entry = Box::leak(Box::new(entry));
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<VmiKvmDriver<Amd64>>::new(&profile)?;

    let core = Box::leak(Box::new(core));
    let os = Box::leak(Box::new(os));

    let session = VmiSession::new(core, os);

    // Find explorer.exe while paused.
    let explorer_pid = {
        let _pause_guard = session.pause_guard()?;

        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);

        let explorer = vmi
            .os()
            .processes()?
            .into_iter()
            .filter_map(|p| p.ok())
            .find(|p| {
                p.name()
                    .map(|n| n.to_lowercase() == "explorer.exe")
                    .unwrap_or(false)
            });

        let explorer = match explorer {
            Some(explorer) => explorer,
            None => {
                tracing::error!("explorer.exe not found");
                return Ok(());
            }
        };

        tracing::info!(
            pid = %explorer.id()?,
            object = %explorer.object()?,
            "found explorer.exe"
        );

        explorer.id()?
    };

    session.handle(|session| {
        UserInjectorHandler::new(
            session,
            recipe_factory(MessageBox::new(
                "Hello, World!",
                "This is a message box from the VMI!",
            )),
        )?
        .with_pid(explorer_pid)
    })?;

    Ok(())
}
