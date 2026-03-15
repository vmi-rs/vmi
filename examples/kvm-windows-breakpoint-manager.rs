use std::fs;
use std::os::fd::RawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use isr::{
    Profile,
    cache::{IsrCache, JsonCodec},
    macros::symbols,
};
use vmi::{
    Hex, MemoryAccess, Va, VcpuId, View, VmiContext, VmiCore, VmiError, VmiEventResponse,
    VmiHandler, VmiSession,
    arch::amd64::{Amd64, EventMonitor, EventReason, ExceptionVector},
    driver::VmiFullDriver,
    os::{
        ProcessObject, VmiOsProcess as _,
        windows::{WindowsFileObject, WindowsOs, WindowsOsExt as _},
    },
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        ptm::PageTableMonitor,
    },
};
use vmi_driver_kvm::VmiKvmDriver;

symbols! {
    #[derive(Debug)]
    pub struct Symbols {
        NtCreateFile: u64,
        NtWriteFile: u64,

        PspInsertProcess: u64,
        MmCleanProcessAddressSpace: u64,
    }
}

/// Discover QEMU process and its KVM fd layout from /proc.
///
/// If `target_pid` is provided, use that PID directly. Otherwise scan /proc.
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

    eprintln!(
        "Duplicated: vm_fd={vm_fd}, vcpu_fds={:?}",
        vcpu_fds
    );

    Ok((pid, vm_fd, vcpu_fds))
}

pub struct Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: View,
    bpm: BreakpointManager<BreakpointController<Driver>>,
    ptm: PageTableMonitor<Driver>,
}

#[expect(non_snake_case)]
impl<Driver> Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    pub fn new(
        session: &VmiSession<WindowsOs<Driver>>,
        profile: &Profile,
        terminate_flag: Arc<AtomicBool>,
    ) -> Result<Self, VmiError> {
        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);

        let kernel_image_base = vmi.os().kernel_image_base()?;
        tracing::info!(%kernel_image_base);

        let system_process = vmi.os().system_process()?;
        tracing::info!(system_process = %system_process.object()?);

        let root = system_process.translation_root()?;
        tracing::info!(%root);

        let symbols = Symbols::new(profile)?;

        vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        let mut bpm = BreakpointManager::new();
        let mut ptm = PageTableMonitor::new();

        let _pause_guard = vmi.pause_guard()?;

        // Insert breakpoint for the NtCreateFile function.
        let va_NtCreateFile = kernel_image_base + symbols.NtCreateFile;
        let cx_NtCreateFile = (va_NtCreateFile, root);
        let bp_NtCreateFile = Breakpoint::new(cx_NtCreateFile, view)
            .global()
            .with_tag("NtCreateFile");
        bpm.insert(&vmi, bp_NtCreateFile)?;
        //ptm.monitor(&vmi, cx_NtCreateFile, view, "NtCreateFile")?;
        tracing::info!(%va_NtCreateFile);

        // Insert breakpoint for the NtWriteFile function.
        let va_NtWriteFile = kernel_image_base + symbols.NtWriteFile;
        let cx_NtWriteFile = (va_NtWriteFile, root);
        let bp_NtWriteFile = Breakpoint::new(cx_NtWriteFile, view)
            .global()
            .with_tag("NtWriteFile");
        bpm.insert(&vmi, bp_NtWriteFile)?;
        //ptm.monitor(&vmi, cx_NtWriteFile, view, "NtWriteFile")?;
        tracing::info!(%va_NtWriteFile);

        // Insert breakpoint for the PspInsertProcess function.
        let va_PspInsertProcess = kernel_image_base + symbols.PspInsertProcess;
        let cx_PspInsertProcess = (va_PspInsertProcess, root);
        let bp_PspInsertProcess = Breakpoint::new(cx_PspInsertProcess, view)
            .global()
            .with_tag("PspInsertProcess");
        bpm.insert(&vmi, bp_PspInsertProcess)?;
        //ptm.monitor(&vmi, cx_PspInsertProcess, view, "PspInsertProcess")?;

        // Insert breakpoint for the MmCleanProcessAddressSpace function.
        let va_MmCleanProcessAddressSpace = kernel_image_base + symbols.MmCleanProcessAddressSpace;
        let cx_MmCleanProcessAddressSpace = (va_MmCleanProcessAddressSpace, root);
        let bp_MmCleanProcessAddressSpace = Breakpoint::new(cx_MmCleanProcessAddressSpace, view)
            .global()
            .with_tag("MmCleanProcessAddressSpace");
        bpm.insert(&vmi, bp_MmCleanProcessAddressSpace)?;
        //ptm.monitor(
        //    &vmi,
        //    cx_MmCleanProcessAddressSpace,
        //    view,
        //    "MmCleanProcessAddressSpace",
        //)?;

        Ok(Self {
            terminate_flag,
            view,
            bpm,
            ptm,
        })
    }

    fn memory_access(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        tracing::trace!(
            pa = %memory_access.pa,
            va = %memory_access.va,
            access = %memory_access.access,
        );

        if memory_access.access.contains(MemoryAccess::W) {
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());

            Ok(VmiEventResponse::singlestep().with_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
        }
        else {
            panic!("Unhandled memory access: {memory_access:?}");
        }
    }

    fn interrupt(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let regs = vmi.registers();
        tracing::debug!(
            rip = %Hex(regs.rip),
            rcx = %Hex(regs.rcx),
            rdx = %Hex(regs.rdx),
            r8 = %Hex(regs.r8),
            gs_base = %Hex(regs.gs.base),
            shadow_gs = %Hex(regs.shadow_gs),
            cs_sel = regs.cs.selector.0,
            cr3 = %Hex(u64::from(regs.cr3)),
            "breakpoint registers"
        );

        let tag = match self.bpm.get_by_event(vmi.event(), ()) {
            Some(breakpoints) => {
                let first_breakpoint = breakpoints.into_iter().next().expect("breakpoint");
                first_breakpoint.tag()
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    tracing::warn!("Unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                else {
                    tracing::warn!("Ignoring old breakpoint event");
                    return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
                }
            }
        };

        tracing::debug!(tag, "getting current_process");
        let process = vmi.os().current_process()?;
        tracing::debug!(tag, process = %process.object()?, "got process, reading id");
        let process_id = process.id()?;
        tracing::debug!(tag, %process_id, "got id, reading name");
        let process_name = process.name()?;
        tracing::debug!(tag, %process_id, process_name, "dispatch to handler");
        tracing::Span::current()
            .record("pid", process_id.0)
            .record("process", &process_name);

        match tag {
            "NtCreateFile" => self.NtCreateFile(vmi)?,
            "NtWriteFile" => self.NtWriteFile(vmi)?,
            "PspInsertProcess" => self.PspInsertProcess(vmi)?,
            "MmCleanProcessAddressSpace" => self.MmCleanProcessAddressSpace(vmi)?,
            _ => panic!("Unhandled tag: {tag}"),
        }

        Ok(VmiEventResponse::fast_singlestep(vmi.default_view()))
    }

    fn singlestep(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;
        self.bpm.handle_ptm_events(vmi, ptm_events)?;

        Ok(VmiEventResponse::default().with_view(self.view))
    }

    fn NtCreateFile(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        let ObjectAttributes = Va(vmi.os().function_argument(2)?);
        tracing::debug!(%ObjectAttributes, "NtCreateFile: reading ObjectAttributes");

        let object_attributes = vmi.os().object_attributes(ObjectAttributes)?;
        tracing::debug!("NtCreateFile: got object_attributes, reading name");
        let object_name = match object_attributes.object_name()? {
            Some(object_name) => object_name,
            None => {
                tracing::warn!(%ObjectAttributes, "No object name found");
                return Ok(());
            }
        };

        tracing::info!(%object_name);

        Ok(())
    }

    fn NtWriteFile(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        let FileHandle = vmi.os().function_argument(0)?;

        let file_object = match vmi
            .os()
            .current_process()?
            .lookup_object::<WindowsFileObject<_>>(FileHandle)?
        {
            Some(file_object) => file_object,
            None => {
                tracing::warn!(FileHandle = %Hex(FileHandle), "No object found");
                return Ok(());
            }
        };

        let path = file_object.full_path()?;
        tracing::info!(%path);

        Ok(())
    }

    fn PspInsertProcess(&mut self, vmi: &VmiContext<WindowsOs<Driver>>) -> Result<(), VmiError> {
        let NewProcess = vmi.os().function_argument(0)?;
        let Parent = vmi.os().function_argument(1)?;

        let process = vmi.os().process(ProcessObject(Va(NewProcess)))?;
        let process_id = process.id()?;

        let parent_process = vmi.os().process(ProcessObject(Va(Parent)))?;
        let parent_process_id = parent_process.id()?;

        debug_assert_eq!(parent_process_id, process.parent_id()?);

        let name = process.name()?;
        let image_base = process.image_base()?;
        let peb = process.peb()?;

        tracing::info!(
            %process_id,
            name,
            %image_base,
            ?peb,
        );

        Ok(())
    }

    fn MmCleanProcessAddressSpace(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        let Process = vmi.os().function_argument(0)?;

        let process = vmi.os().process(ProcessObject(Va(Process)))?;
        let process_id = process.id()?;

        let name = process.name()?;
        let image_base = process.image_base()?;

        tracing::info!(%process_id, name, %image_base);

        Ok(())
    }

    fn dispatch(
        &mut self,
        vmi: &VmiContext<WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let event = vmi.event();
        let result = match event.reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            EventReason::Singlestep(_) => self.singlestep(vmi),
            _ => panic!("Unhandled event: {:?}", event.reason()),
        };

        if let Err(VmiError::Translation(ref pfs)) = result {
            let regs = vmi.registers();
            tracing::warn!(
                ?pfs,
                rip = %Hex(regs.rip),
                gs_base = %Hex(regs.gs.base),
                shadow_gs = %Hex(regs.shadow_gs),
                cs_sel = regs.cs.selector.0,
                event = ?event.reason(),
                "Translation error (NOT injecting PF)"
            );
            // Don't inject PF for bogus addresses like 0x10.
            // Use fast_singlestep to step over the breakpoint in view 0
            // and return to view 1 on the next instruction.
            return Ok(VmiEventResponse::fast_singlestep(vmi.default_view()));
        }

        result
    }
}

impl<Driver> VmiHandler<WindowsOs<Driver>> for Monitor<Driver>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    type Output = ();

    fn handle_event(&mut self, vmi: VmiContext<WindowsOs<Driver>>) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        self.dispatch(&vmi).expect("dispatch")
    }

    fn poll(&self) -> Option<Self::Output> {
        self.terminate_flag.load(Ordering::Relaxed).then_some(())
    }
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
    eprintln!("Creating VMI session...");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiKvmDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    eprintln!("Starting breakpoint manager (Ctrl+C to stop)...");
    session.handle(|session| Monitor::new(session, &profile, terminate_flag))?;

    Ok(())
}
