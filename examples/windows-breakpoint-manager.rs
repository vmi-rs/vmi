use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use isr::{
    cache::{IsrCache, JsonCodec},
    macros::symbols,
    Profile,
};
use vmi::{
    arch::amd64::{Amd64, EventMonitor, EventReason, ExceptionVector, Interrupt},
    driver::xen::VmiXenDriver,
    os::{
        windows::{WindowsOs, WindowsOsExt as _},
        ProcessObject, VmiOsProcess as _,
    },
    utils::{
        bpm::{Breakpoint, BreakpointController, BreakpointManager},
        ptm::{PageTableMonitor, PageTableMonitorEvent},
    },
    Hex, MemoryAccess, Va, VcpuId, View, VmiContext, VmiCore, VmiDriver, VmiError,
    VmiEventResponse, VmiHandler, VmiSession,
};
use xen::XenStore;

symbols! {
    #[derive(Debug)]
    pub struct Symbols {
        NtCreateFile: u64,
        NtWriteFile: u64,

        PspInsertProcess: u64,
        MmCleanProcessAddressSpace: u64,

        // `symbols!` macro also accepts an `Option<u64>` as a value,
        // where `None` means that the symbol is not present in the profile.
        // MiInsertVad: Option<u64>,
        // MiInsertPrivateVad: Option<u64>,
        // MiGetWsAndInsertVad: Option<u64>,
        // MiDeleteVad: Option<u64>,
        // MiDeletePartialVad: Option<u64>,
        // MiDeleteVirtualAddresses: Option<u64>,
        // MiRemoveVadAndView: Option<u64>,
    }
}

pub struct Monitor<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    terminate_flag: Arc<AtomicBool>,
    view: View,
    bpm: BreakpointManager<BreakpointController<Driver>>,
    ptm: PageTableMonitor<Driver>,
}

#[expect(non_snake_case)]
impl<Driver> Monitor<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    pub fn new(
        session: &VmiSession<Driver, WindowsOs<Driver>>,
        profile: &Profile,
        terminate_flag: Arc<AtomicBool>,
    ) -> Result<Self, VmiError> {
        // Capture the current state of the VCPU and get the base address of
        // the kernel.
        //
        // This base address is essential to correctly offset monitored
        // functions.
        //
        // NOTE: `kernel_image_base` tries to find the kernel in the memory
        //       with the help of the CPU registers. On AMD64 architecture,
        //       the kernel image base is usually found using the `MSR_LSTAR`
        //       register, which contains the address of the system call
        //       handler. This register is set by the operating system during
        //       boot and is left unchanged (unless some rootkits are involved).
        //
        //       Therefore, we can take an arbitrary registers at any point
        //       in time (as long as the OS has booted and the page tables are
        //       set up) and use them to find the kernel image base.
        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);

        let kernel_image_base = vmi.os().kernel_image_base()?;
        tracing::info!(%kernel_image_base);

        // Get the system process.
        //
        // The system process is the first process created by the kernel.
        // In Windows, it is referenced by the kernel symbol `PsInitialSystemProcess`.
        // To monitor page table entries, we need to locate the translation root
        // of this process.
        let system_process = vmi.os().system_process()?;
        tracing::info!(system_process = %system_process.object()?);

        // Get the translation root of the system process.
        // This is effectively "the CR3 of the kernel".
        //
        // The translation root is the root of the page table hierarchy (also
        // known as the Directory Table Base or PML4).
        let root = system_process.translation_root()?;
        tracing::info!(%root);

        // Load the symbols from the profile.
        let symbols = Symbols::new(profile)?;

        // Enable monitoring of the INT3 and singlestep events.
        //
        // INT3 is used to monitor the execution of specific functions.
        // Singlestep is used to monitor the modifications of page table
        // entries.
        vmi.monitor_enable(EventMonitor::Interrupt(ExceptionVector::Breakpoint))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        // Create a new view for the monitor.
        // This view is used for monitoring function calls and memory accesses.
        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;

        // Create a new breakpoint controller.
        //
        // The breakpoint controller is used to insert breakpoints for specific
        // functions.
        //
        // From the guest's perspective, these breakpoints are "hidden", since
        // the breakpoint controller will unset the read/write access to the
        // physical memory page where the breakpoint is inserted, while keeping
        // the execute access.
        //
        // This way, the guest will be able to execute the code, but attempts to
        // read or write the memory will trigger the `memory_access` callback.
        //
        // When a VCPU tries to execute the breakpoint instruction:
        // - an `interrupt` callback will be triggered
        // - the breakpoint will be handled (e.g., log the function call)
        // - a fast-singlestep[1] will be performed over the INT3 instruction
        //
        // When a VCPU tries to read from this page (e.g., a PatchGuard check):
        // - `memory_access` callback will be triggered (with the `MemoryAccess::R`
        //   access type)
        // - fast-singlestep[1] will be performed over the instruction that tried to
        //   read the memory
        //
        // This way, the instruction will read the original memory content.
        //
        // [1] Fast-singlestep is a VMI feature that allows to switch the VCPU
        //     to a different view, execute a single instruction, and then
        //     switch back to the original view. In this case, the view is
        //     switched to the `default_view` (which is unmodified).
        let mut bpm = BreakpointManager::new();

        // Create a new page table monitor.
        //
        // The page table monitor is used to monitor the page table entries of
        // the hooked functions.
        //
        // More specifically, it is used to monitor the pages that the breakpoint
        // was inserted into. This is necessary to handle the case when the
        // page containing the breakpoint is paged out (and then paged in
        // again).
        //
        // `PageTableMonitor` works by unsetting the write access to the page
        // tables of the hooked functions. When the page is paged out, the
        // `PRESENT` bit in the page table entry is unset and, conversely, when
        // the page is paged in, the `PRESENT` bit is set again.
        //
        // When that happens:
        // - the `memory_access` callback will be triggered (with the `MemoryAccess::R`
        //   access type)
        // - the callback will mark the page as dirty in the page table monitor
        // - a singlestep will be performed over the instruction that tried to modify
        //   the memory containing the page table entry
        // - the `singlestep` handler will process the dirty page table entries and
        //   inform the breakpoint controller to handle the changes
        let mut ptm = PageTableMonitor::new();

        // Pause the VM to avoid race conditions between inserting breakpoints
        // and monitoring page table entries. The VM resumes when the pause
        // guard is dropped.
        let _pause_guard = vmi.pause_guard()?;

        // Insert breakpoint for the `NtCreateFile` function.
        let va_NtCreateFile = kernel_image_base + symbols.NtCreateFile;
        let cx_NtCreateFile = (va_NtCreateFile, root);
        let bp_NtCreateFile = Breakpoint::new(cx_NtCreateFile, view)
            .global()
            .with_tag("NtCreateFile");
        bpm.insert(&vmi, bp_NtCreateFile)?;
        ptm.monitor(&vmi, cx_NtCreateFile, view, "NtCreateFile")?;
        tracing::info!(%va_NtCreateFile);

        // Insert breakpoint for the `NtWriteFile` function.
        let va_NtWriteFile = kernel_image_base + symbols.NtWriteFile;
        let cx_NtWriteFile = (va_NtWriteFile, root);
        let bp_NtWriteFile = Breakpoint::new(cx_NtWriteFile, view)
            .global()
            .with_tag("NtWriteFile");
        bpm.insert(&vmi, bp_NtWriteFile)?;
        ptm.monitor(&vmi, cx_NtWriteFile, view, "NtWriteFile")?;
        tracing::info!(%va_NtWriteFile);

        // Insert breakpoint for the `PspInsertProcess` function.
        let va_PspInsertProcess = kernel_image_base + symbols.PspInsertProcess;
        let cx_PspInsertProcess = (va_PspInsertProcess, root);
        let bp_PspInsertProcess = Breakpoint::new(cx_PspInsertProcess, view)
            .global()
            .with_tag("PspInsertProcess");
        bpm.insert(&vmi, bp_PspInsertProcess)?;
        ptm.monitor(&vmi, cx_PspInsertProcess, view, "PspInsertProcess")?;

        // Insert breakpoint for the `MmCleanProcessAddressSpace` function.
        let va_MmCleanProcessAddressSpace = kernel_image_base + symbols.MmCleanProcessAddressSpace;
        let cx_MmCleanProcessAddressSpace = (va_MmCleanProcessAddressSpace, root);
        let bp_MmCleanProcessAddressSpace = Breakpoint::new(cx_MmCleanProcessAddressSpace, view)
            .global()
            .with_tag("MmCleanProcessAddressSpace");
        bpm.insert(&vmi, bp_MmCleanProcessAddressSpace)?;
        ptm.monitor(
            &vmi,
            cx_MmCleanProcessAddressSpace,
            view,
            "MmCleanProcessAddressSpace",
        )?;

        Ok(Self {
            terminate_flag,
            view,
            bpm,
            ptm,
        })
    }

    #[tracing::instrument(skip_all)]
    fn memory_access(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let memory_access = vmi.event().reason().as_memory_access();

        tracing::trace!(
            pa = %memory_access.pa,
            va = %memory_access.va,
            access = %memory_access.access,
        );

        if memory_access.access.contains(MemoryAccess::W) {
            // It is assumed that a write memory access event is caused by a
            // page table modification.
            //
            // The page table entry is marked as dirty in the page table monitor
            // and a singlestep is performed to process the dirty entries.
            self.ptm
                .mark_dirty_entry(memory_access.pa, self.view, vmi.event().vcpu_id());

            Ok(VmiEventResponse::toggle_singlestep().and_set_view(vmi.default_view()))
        }
        else if memory_access.access.contains(MemoryAccess::R) {
            // When the guest tries to read from the memory, a fast-singlestep
            // is performed over the instruction that tried to read the memory.
            // This is done to allow the instruction to read the original memory
            // content.
            Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()))
        }
        else {
            panic!("Unhandled memory access: {memory_access:?}");
        }
    }

    #[tracing::instrument(skip_all, fields(pid, process))]
    fn interrupt(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let tag = match self.bpm.get_by_event(vmi.event(), ()) {
            Some(breakpoints) => {
                // Breakpoints can have multiple tags, but we have set only one
                // tag for each breakpoint.
                let first_breakpoint = breakpoints.into_iter().next().expect("breakpoint");
                first_breakpoint.tag()
            }
            None => {
                if BreakpointController::is_breakpoint(vmi, vmi.event())? {
                    // This breakpoint was not set by us. Reinject it.
                    tracing::warn!("Unknown breakpoint, reinjecting");
                    return Ok(VmiEventResponse::reinject_interrupt());
                }
                else {
                    // We have received a breakpoint event, but there is no
                    // breakpoint instruction at the current memory location.
                    // This can happen if the event was triggered by a breakpoint
                    // we just removed.
                    tracing::warn!("Ignoring old breakpoint event");
                    return Ok(
                        VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view())
                    );
                }
            }
        };

        let process = vmi.os().current_process()?;
        let process_id = process.id()?;
        let process_name = process.name()?;
        tracing::Span::current()
            .record("pid", process_id.0)
            .record("process", process_name);

        match tag {
            "NtCreateFile" => self.NtCreateFile(vmi)?,
            "NtWriteFile" => self.NtWriteFile(vmi)?,
            "PspInsertProcess" => self.PspInsertProcess(vmi)?,
            "MmCleanProcessAddressSpace" => self.MmCleanProcessAddressSpace(vmi)?,
            _ => panic!("Unhandled tag: {tag}"),
        }

        Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()))
    }

    #[tracing::instrument(skip_all)]
    fn singlestep(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        // Get the page table modifications by processing the dirty page table
        // entries.
        let ptm_events = self.ptm.process_dirty_entries(vmi, vmi.event().vcpu_id())?;

        for event in &ptm_events {
            // Log the page table modifications.
            match &event {
                PageTableMonitorEvent::PageIn(update) => tracing::debug!(?update, "page-in"),
                PageTableMonitorEvent::PageOut(update) => tracing::debug!(?update, "page-out"),
            }

            // Let the breakpoint controller handle the page table modifications.
            self.bpm.handle_ptm_event(vmi, event)?;
        }

        // Disable singlestep and switch back to our view.
        Ok(VmiEventResponse::toggle_singlestep().and_set_view(self.view))
    }

    #[tracing::instrument(skip_all)]
    fn NtCreateFile(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        //
        // NTSTATUS
        // NtCreateFile (
        //     _Out_ PHANDLE FileHandle,
        //     _In_ ACCESS_MASK DesiredAccess,
        //     _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        //     _In_opt_ PLARGE_INTEGER AllocationSize,
        //     _In_ ULONG FileAttributes,
        //     _In_ ULONG ShareAccess,
        //     _In_ ULONG CreateDisposition,
        //     _In_ ULONG CreateOptions,
        //     _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        //     _In_ ULONG EaLength
        //     );
        //

        let ObjectAttributes = Va(vmi.os().function_argument(2)?);

        let object_attributes = vmi.os().object_attributes(ObjectAttributes)?;
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

    #[tracing::instrument(skip_all)]
    fn NtWriteFile(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        //
        // NTSTATUS
        // NtWriteFile (
        //     _In_ HANDLE FileHandle,
        //     _In_opt_ HANDLE Event,
        //     _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        //     _In_opt_ PVOID ApcContext,
        //     _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        //     _In_reads_bytes_(Length) PVOID Buffer,
        //     _In_ ULONG Length,
        //     _In_opt_ PLARGE_INTEGER ByteOffset,
        //     _In_opt_ PULONG Key
        //     );
        //

        let FileHandle = vmi.os().function_argument(0)?;

        let handle_table = match vmi.os().current_process()?.handle_table()? {
            Some(handle_table) => handle_table,
            None => {
                tracing::warn!("No handle table found");
                return Ok(());
            }
        };

        let handle_table_entry = match handle_table.lookup(FileHandle)? {
            Some(handle_table_entry) => handle_table_entry,
            None => {
                tracing::warn!(FileHandle = %Hex(FileHandle), "No handle table entry found");
                return Ok(());
            }
        };

        let object = match handle_table_entry.object()? {
            Some(object) => object,
            None => {
                tracing::warn!(FileHandle = %Hex(FileHandle), "No object found");
                return Ok(());
            }
        };

        let file_object = match object.as_file()? {
            Some(file_object) => file_object,
            None => {
                tracing::warn!(FileHandle = %Hex(FileHandle), "Not a file object");
                return Ok(());
            }
        };

        let path = file_object.full_path()?;
        tracing::info!(%path);

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    fn PspInsertProcess(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        //
        // NTSTATUS
        // PspInsertProcess (
        //     _In_ PEPROCESS NewProcess,
        //     _In_ PEPROCESS Parent,
        //     _In_ ULONG DesiredAccess,
        //     _In_ ULONG CreateFlags,
        //     ...
        //     );
        //

        let NewProcess = vmi.os().function_argument(0)?;
        let Parent = vmi.os().function_argument(1)?;

        let process = vmi.os().process(ProcessObject(Va(NewProcess)))?;
        let process_id = process.id()?;

        let parent_process = vmi.os().process(ProcessObject(Va(Parent)))?;
        let parent_process_id = parent_process.id()?;

        // We rely heavily on the 2nd argument to be the parent process object.
        // If that ever changes, this assertion should catch it.
        //
        // So far it is verified that it works for Windows 7 up to Windows 11
        // (23H2, build 22631).
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

    #[tracing::instrument(skip_all)]
    fn MmCleanProcessAddressSpace(
        &mut self,
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<(), VmiError> {
        //
        // VOID
        // MmCleanProcessAddressSpace (
        //     _In_ PEPROCESS Process
        //     );
        //

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
        vmi: &VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        let event = vmi.event();
        let result = match event.reason() {
            EventReason::MemoryAccess(_) => self.memory_access(vmi),
            EventReason::Interrupt(_) => self.interrupt(vmi),
            EventReason::Singlestep(_) => self.singlestep(vmi),
            _ => panic!("Unhandled event: {:?}", event.reason()),
        };

        // If VMI tries to read from a page that is not present, it will return
        // a page fault error. In this case, we inject a page fault interrupt
        // to the guest.
        //
        // Once the guest handles the page fault, it will retry to execute the
        // instruction that caused the page fault.
        if let Err(VmiError::Translation(pfs)) = result {
            tracing::warn!(?pfs, "Page fault, injecting");
            vmi.inject_interrupt(event.vcpu_id(), Interrupt::page_fault(pfs[0].va, 0))?;
            return Ok(VmiEventResponse::default());
        }

        result
    }
}

impl<Driver> VmiHandler<Driver, WindowsOs<Driver>> for Monitor<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    type Output = ();

    fn handle_event(
        &mut self,
        vmi: VmiContext<'_, Driver, WindowsOs<Driver>>,
    ) -> VmiEventResponse<Amd64> {
        // Flush the V2P cache on every event to avoid stale translations.
        vmi.flush_v2p_cache();

        self.dispatch(&vmi).expect("dispatch")
    }

    fn check_completion(&self) -> Option<Self::Output> {
        self.terminate_flag.load(Ordering::Relaxed).then_some(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let domain_id = 'x: {
        for name in &["win7", "win10", "win11", "ubuntu22"] {
            if let Some(domain_id) = XenStore::domain_id_from_name(name)? {
                break 'x domain_id;
            }
        }

        panic!("Domain not found");
    };

    tracing::debug!(?domain_id);

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let regs = core.registers(0.into())?;

        WindowsOs::find_kernel(&core, &regs)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
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

    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    session.handle(|session| Monitor::new(session, &profile, terminate_flag))?;

    Ok(())
}
