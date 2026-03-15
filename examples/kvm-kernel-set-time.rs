use std::fs;
use std::os::fd::RawFd;
use std::sync::{Arc, atomic::AtomicBool};

use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    Va, VcpuId, VmiCore, VmiError, VmiEventControl, VmiSession,
    arch::amd64::Amd64,
    driver::{
        VmiQueryRegisters, VmiRead, VmiSetProtection, VmiSetRegisters, VmiViewControl,
        VmiVmControl, VmiWrite,
    },
    os::windows::WindowsOs,
    utils::injector::{InjectorHandler, KernelMode, Recipe, recipe},
};
use vmi_driver_kvm::VmiKvmDriver;

#[derive(Debug, Default)]
pub struct RecipeData {
    system_time_va: Va,
    previous_time_va: Va,
}

pub fn recipe_factory<Driver>() -> Recipe<WindowsOs<Driver>, RecipeData>
where
    Driver: VmiRead<Architecture = Amd64> + VmiWrite<Architecture = Amd64>,
{
    recipe![
        Recipe::<WindowsOs<Driver>, _>::new(RecipeData::default()),
        //
        // Step 1: Allocate memory from the non-paged pool.
        //         This guarantees that the memory will be present for the
        //         next step in the physical memory.
        //
        {
            tracing::debug!("[step 1]");

            const fn create_windows_time(
                year: u64,
                month: u64,
                day: u64,
                hour: u64,
                minute: u64,
                second: u64,
            ) -> u64 {
                // Days from years (accounting for leap years)
                let mut total_days: u64 = 0;
                let mut y = 1601;
                while y < year {
                    if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
                        total_days += 366;
                    }
                    else {
                        total_days += 365;
                    }
                    y += 1;
                }

                // Days from months
                let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
                let month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                let mut m = 1;
                while m < month {
                    total_days += month_days[(m - 1) as usize];
                    if m == 2 && is_leap {
                        total_days += 1;
                    }
                    m += 1;
                }

                // Days
                total_days += day - 1;

                // Convert to 100-nanosecond intervals
                let total_seconds = total_days * 86400 + hour * 3600 + minute * 60 + second;
                total_seconds * 10_000_000
            }

            const NEW_SYSTEM_TIME: u64 = create_windows_time(2025, 2, 4, 9, 9, 9);

            data![system_time_va] = copy_to_stack!(NEW_SYSTEM_TIME)?;
            data![previous_time_va] = copy_to_stack!(0u64)?;

            inject! {
                nt!ZwSetSystemTime(
                    data![system_time_va],    // SystemTime
                    data![previous_time_va]   // PreviousTime
                )
            }
        },
    ]
}

pub fn injector_handler_factory<Driver>() -> impl FnOnce(
    &VmiSession<WindowsOs<Driver>>,
) -> Result<
    InjectorHandler<WindowsOs<Driver>, KernelMode, RecipeData>,
    VmiError,
>
where
    Driver: VmiRead<Architecture = Amd64>
        + VmiWrite<Architecture = Amd64>
        + VmiSetProtection<Architecture = Amd64>
        + VmiQueryRegisters<Architecture = Amd64>
        + VmiSetRegisters<Architecture = Amd64>
        + VmiEventControl<Architecture = Amd64>
        + VmiViewControl<Architecture = Amd64>
        + VmiVmControl<Architecture = Amd64>,
{
    move |session| InjectorHandler::new(session, recipe_factory())
}

/// Discover QEMU process and its KVM fd layout from /proc.
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

    eprintln!(
        "Duplicated: vm_fd={vm_fd}, vcpu_fds={:?}",
        vcpu_fds
    );

    Ok((pid, vm_fd, vcpu_fds))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
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
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    session.handle(injector_handler_factory())?;

    Ok(())
}
