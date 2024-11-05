use isr_core::Profile;
use isr_macros::{offsets, Field};
use vmi_arch_amd64::{Amd64, ControlRegister, EventMonitor, EventReason, Interrupt, Registers};
use vmi_core::{
    os::ProcessId, Architecture as _, Hex, MemoryAccess, Registers as _, Va, View, VmiContext,
    VmiCore, VmiDriver, VmiError, VmiEventResponse, VmiHandler,
};
use vmi_os_windows::{WindowsOs, WindowsOsExt as _};

use super::{
    super::{arch::ArchAdapter as _, CallBuilder, InjectorHandler, Recipe, RecipeExecutor},
    OsAdapter,
};

// const INVALID_VA: Va = Va(0xffff_ffff_ffff_ffff);
const INVALID_VIEW: View = View(0xffff);
// const INVALID_TID: ThreadId = ThreadId(0xffff_ffff);
// const INVALID_PID: ProcessId = ProcessId(0xffff_ffff);

offsets! {
    #[derive(Debug)]
    pub struct Offsets {
        struct _KTRAP_FRAME {
            Rip: Field,
            Rsp: Field,
        }

        struct _KTHREAD {
            TrapFrame: Field,
        }
    }
}

impl<Driver> OsAdapter<Driver> for WindowsOs<Driver>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    type Offsets = Offsets;

    fn prepare_function_call(
        &self,
        vmi: &VmiCore<Driver>,
        registers: &mut Registers,
        builder: CallBuilder,
    ) -> Result<(), VmiError> {
        tracing::trace!(
            rsp = %Hex(registers.rsp),
            rip = %Hex(registers.rip),
            "preparing function call"
        );

        let arguments = Amd64::push_arguments(vmi, registers, &builder.arguments)?;

        tracing::trace!(
            rsp = %Hex(registers.rsp),
            "pushed arguments"
        );

        let mut addr = registers.rsp;

        let nb_args = arguments.len();

        // According to Microsoft Doc "Building C/C++ Programs":
        // > The stack will always be maintained 16-byte aligned, except within the
        // > prolog
        // > (for example, after the return address is pushed), and except where
        // > indicated
        // > in Function Types for a certain class of frame functions.
        //
        // Add padding to be aligned to "16+8" boundary.
        //
        // https://www.gamasutra.com/view/news/178446/Indepth_Windows_x64_ABI_Stack_frames.php
        //
        // This padding on the stack only exists if the maximum number of parameters
        // passed to functions is greater than 4 and is an odd number.
        let effective_nb_args = nb_args.max(4) as u64;
        if (addr - effective_nb_args * 0x8 - 0x8) & 0xf != 8 {
            addr -= 0x8;

            tracing::trace!(
                addr = %Hex(addr),
                "aligning stack"
            );
        }

        // http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        // First 4 parameters to functions are always passed in registers
        // P1=rcx, P2=rdx, P3=r8, P4=r9
        // 5th parameter onwards (if any) passed via the stack

        // write parameters (5th onwards) into guest's stack
        for index in (4..nb_args).rev() {
            addr -= 0x8;
            vmi.write_u64((addr.into(), registers.cr3.into()), arguments[index])?;

            tracing::trace!(
                index,
                value = %Hex(arguments[index]),
                addr = %Hex(addr),
                "argument (stack)"
            );
        }

        // write the first 4 parameters into registers
        if nb_args > 3 {
            registers.r9 = arguments[3];

            tracing::trace!(
                index = 3,
                value = %Hex(arguments[3]),
                "argument"
            );
        }

        if nb_args > 2 {
            registers.r8 = arguments[2];

            tracing::trace!(
                index = 2,
                value = %Hex(arguments[2]),
                "argument"
            );
        }

        if nb_args > 1 {
            registers.rdx = arguments[1];

            tracing::trace!(
                index = 1,
                value = %Hex(arguments[1]),
                "argument"
            );
        }

        if nb_args > 0 {
            registers.rcx = arguments[0];

            tracing::trace!(
                index = 0,
                value = %Hex(arguments[0]),
                "argument"
            );
        }

        // allocate 0x20 "homing space"
        addr -= 0x20;

        // save the return address
        addr -= 0x8;
        vmi.write_u64((addr.into(), registers.cr3.into()), registers.rip)?;

        // grow the stack
        registers.rsp = addr;

        // set the new instruction pointer
        registers.rip = builder.function_address.into();

        tracing::trace!(
            rsp = %Hex(registers.rsp),
            rip = %Hex(registers.rip),
            "finished preparing function call"
        );

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<Driver, T> InjectorHandler<Driver, WindowsOs<Driver>, T>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    /// Creates a new injector handler.
    pub fn new(
        vmi: &VmiCore<Driver>,
        profile: &Profile,
        pid: ProcessId,
        recipe: Recipe<Driver, WindowsOs<Driver>, T>,
    ) -> Result<Self, VmiError> {
        let offsets = Offsets::new(profile)?;

        let view = vmi.create_view(MemoryAccess::RWX)?;
        vmi.switch_to_view(view)?;
        vmi.monitor_enable(EventMonitor::CpuId)?;
        vmi.monitor_enable(EventMonitor::Register(ControlRegister::Cr3))?;
        vmi.monitor_enable(EventMonitor::Singlestep)?;

        Ok(Self {
            pid,
            tid: None,
            hijacked: false,
            sp_va: None,
            ip_va: None,
            ip_pa: None,
            offsets,
            recipe: RecipeExecutor::new(recipe),
            view,
            bridge: false,
            finished: false,
        })
    }

    #[tracing::instrument(
        name = "injector",
        skip_all,
        fields(
            vcpu = %vmi.event().vcpu_id(),
            rip = %Va(vmi.registers().rip),
        )
    )]
    fn dispatch(
        &mut self,
        vmi: &VmiContext<Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        match vmi.event().reason() {
            EventReason::MemoryAccess(_) => self.on_memory_access(vmi),
            EventReason::WriteControlRegister(_) => {
                let _ = self.on_write_cr(vmi);
                Ok(VmiEventResponse::default())
            }
            EventReason::CpuId(_) => self.on_cpuid(vmi),
            _ => panic!("Unhandled event: {:?}", vmi.event().reason()),
        }
    }

    #[tracing::instrument(name = "cpuid", skip_all)]
    fn on_cpuid(
        &mut self,
        vmi: &VmiContext<Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        const SYNC_MAGIC_LEAF: u32 = 0x406e7964; // '@nyd'
        const SYNC_MAGIC_RESPONSE: u64 = 0x616e7964; // 'anyd'

        const SYNC_REQUEST_HELLO: u16 = 0x0000;
        const SYNC_REQUEST_STATUS: u16 = 0x8000;
        const SYNC_REQUEST_ERROR: u16 = 0xFFFF;

        const SYNC_LAST_PHASE: u16 = 0xFFFF;

        const SYNC_RESPONSE_WAIT: u64 = 0x00000000;
        const SYNC_RESPONSE_CONTINUE: u64 = 0x00000001;
        const SYNC_RESPONSE_ABORT: u64 = 0xFFFFFFFF;

        let cpuid = vmi.event().reason().as_cpuid();

        let mut registers = vmi.registers().gp_registers();
        registers.rip += cpuid.instruction_length as u64;

        tracing::trace!(
            rip = %Va(registers.rip),
            leaf = %Hex(cpuid.leaf),
            subleaf = %Hex(cpuid.subleaf),
        );

        if cpuid.leaf != SYNC_MAGIC_LEAF {
            // tracing::trace!("not the right leaf");
            return Ok(VmiEventResponse::set_registers(registers));
        }

        let request = (cpuid.subleaf >> 16) as u16;
        let method = (cpuid.subleaf & 0xFFFF) as u16;

        match (request, method) {
            (SYNC_REQUEST_HELLO, _) => {
                tracing::debug!("hello request");
                registers.rax = SYNC_MAGIC_RESPONSE;

                assert!(!self.bridge, "double hello request");
                self.bridge = true;
            }

            (SYNC_REQUEST_STATUS, SYNC_LAST_PHASE) => {
                tracing::debug!("last phase request");
                registers.rax = SYNC_RESPONSE_WAIT;
                self.finished = true;
            }

            (SYNC_REQUEST_STATUS, phase) => {
                tracing::debug!(phase, "status request");
                registers.rax = SYNC_RESPONSE_CONTINUE;
            }

            (SYNC_REQUEST_ERROR, code) => {
                tracing::error!(code, "error request");
                registers.rax = SYNC_RESPONSE_ABORT;
                self.finished = true;
            }

            _ => {
                tracing::error!(request, method, "unknown request");
                registers.rax = SYNC_RESPONSE_ABORT;
                self.finished = true;
            }
        };

        if self.finished {
            vmi.monitor_disable(EventMonitor::CpuId)?;
        };

        registers.rbx = SYNC_MAGIC_RESPONSE;
        registers.rcx = SYNC_MAGIC_RESPONSE;
        registers.rdx = SYNC_MAGIC_RESPONSE;
        Ok(VmiEventResponse::set_registers(registers))
    }

    #[tracing::instrument(name = "write_cr", skip_all)]
    fn on_write_cr(
        &mut self,
        vmi: &VmiContext<Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the thread has already been hijacked.
        // (Besides, in such case, this CR3 monitoring is being disabled anyway.)
        //

        if self.hijacked {
            return Ok(VmiEventResponse::default());
        }

        //
        // Early exit if the current process is not the target process.
        //

        let current_pid = vmi.os().current_process_id()?;
        if current_pid != self.pid {
            return Ok(VmiEventResponse::default());
        }

        //
        // Figure out if the current thread is viable for hijacking.
        // First, fetch the current TID and the next instruction from
        // trap frame of the current thread.
        //

        let current_tid = vmi.os().current_thread_id()?;

        let KTHREAD_TrapFrame = self.offsets._KTHREAD.TrapFrame.offset;
        let KTRAP_FRAME_Rsp = self.offsets._KTRAP_FRAME.Rsp.offset;
        let KTRAP_FRAME_Rip = self.offsets._KTRAP_FRAME.Rip.offset;

        let current_thread = vmi.os().current_thread()?;
        let current_thread = Va::from(current_thread);

        let trap_frame = vmi.read_va(current_thread + KTHREAD_TrapFrame)?;
        let sp_va = vmi.read_va(trap_frame + KTRAP_FRAME_Rsp)?;
        let ip_va = vmi.read_va(trap_frame + KTRAP_FRAME_Rip)?;

        //
        // Verify that the next instruction of this thread is in a user-mode
        // address space.
        //

        if !vmi.os().is_valid_user_address(ip_va)? {
            tracing::trace!(%ip_va, "skipping invalid pc");

            return Ok(VmiEventResponse::default());
        }

        //
        // Translate the instruction pointer to a physical address.
        //

        let ip_pa = match vmi.translate_address(ip_va) {
            Ok(ip_pa) => {
                tracing::trace!(
                    %current_tid,
                    %sp_va,
                    %ip_va,
                    %ip_pa,
                    "trying to hijack thread"
                );

                ip_pa
            }

            Err(err) => {
                tracing::trace!(
                    %current_tid,
                    %sp_va,
                    %ip_va,
                    ip_pa = "error",
                    "trying to hijack thread"
                );

                return Err(err);
            }
        };

        //
        // If we've tried to hijack a thread before, we need to restore the
        // previous memory access permissions.
        //

        if let Some(previous_ip_pa) = self.ip_pa {
            let previous_ip_gfn = Driver::Architecture::gfn_from_pa(previous_ip_pa);
            vmi.set_memory_access(previous_ip_gfn, self.view, MemoryAccess::RWX)?;
        }

        //
        // Set the memory access permissions for the next user-mode instruction.
        // This will unset the eXecute permission for the page containing the
        // next user-mode instruction. This is necessary to trigger a `MemoryAccess`
        // event when the thread resumes execution.
        //

        let ip_gfn = Driver::Architecture::gfn_from_pa(ip_pa);
        vmi.set_memory_access(ip_gfn, self.view, MemoryAccess::RW)?;

        //
        // Mark down the current TID and the VA/PA of the next user-mode instruction.
        // The next `MemoryAccess` handler will try to hijack the thread.
        //

        self.tid = Some(current_tid);
        self.sp_va = Some(sp_va);
        self.ip_va = Some(ip_va);
        self.ip_pa = Some(ip_pa);

        Ok(VmiEventResponse::default())
    }

    #[tracing::instrument(name = "memory_access", skip_all)]
    fn on_memory_access(
        &mut self,
        vmi: &VmiContext<Driver, WindowsOs<Driver>>,
    ) -> Result<VmiEventResponse<Amd64>, VmiError> {
        //
        // Early exit if the memory view is not the target view.
        //

        if vmi.event().view() != Some(self.view) {
            tracing::trace!(
                view = %self.view,
                current_view = %vmi.event().view().unwrap_or(INVALID_VIEW),
                "not the right view"
            );

            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Early exit if the current process is not the target process.
        // Note that some physical memory pages (especially those containing
        // mapped files, such as DLLs) are shared among multiple processes.
        // Therefore this event might have been triggered by a different process.
        //

        let current_pid = vmi.os().current_process_id()?;
        if current_pid != self.pid {
            // Too noisy...
            // tracing::trace!(
            //     pid = %self.pid,
            //     %current_pid,
            //     "not the right process"
            // );
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Early exit if the current thread is not the target thread.
        //

        let current_tid = vmi.os().current_thread_id()?;
        if Some(current_tid) != self.tid {
            // Too noisy...
            // tracing::trace!(
            //     tid = %self.tid.unwrap_or(INVALID_TID),
            //     %current_tid,
            //     "not the right thread"
            // );
            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Early exit if this instruction pointer is not the one we're looking for.
        //

        let registers = vmi.registers();
        let ip = Va(registers.rip);
        if Some(ip) != self.ip_va {
            //tracing::trace!(
            //    ip = %self.ip_va.unwrap_or(INVALID_VA),
            //    current_ip = %ip,
            //    "not the right instruction pointer"
            //);

            return Ok(VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view()));
        }

        //
        // Hijack the thread, save the current registers, and disable CR3 monitoring.
        //

        if !self.hijacked {
            tracing::debug!(%current_tid, "thread hijacked");
            self.hijacked = true;

            vmi.monitor_disable(EventMonitor::Register(ControlRegister::Cr3))?;
        }

        let sp = Va(registers.rsp);
        if let Some(sp_va) = self.sp_va {
            if sp_va > sp {
                tracing::trace!(
                    sp = %sp_va,
                    current_sp = %sp,
                    "not the right stack pointer"
                );

                return Ok(
                    VmiEventResponse::toggle_fast_singlestep().and_set_view(vmi.default_view())
                );
            }
        }

        //
        // Execute the next step in the recipe.
        //

        //println!("BEFORE");
        //println!("RIP: 0x{:016X}", registers.rip);
        //println!("RSP: 0x{:016X}", registers.rsp);
        //let _ = hexdump(vmi, (Va(registers.rsp - 0x200), registers.cr3.into()), 0x400, Representation::U64);

        let new_registers = self.recipe.execute(vmi)?;
        self.sp_va = Some(Va(new_registers.rsp));

        //println!("AFTER");
        //println!("RIP: 0x{:016X}", new_registers.rip);
        //println!("RSP: 0x{:016X}", new_registers.rsp);
        //let _ = hexdump(vmi, (Va(registers.rsp - 0x200), registers.cr3.into()), 0x400, Representation::U64);

        if self.recipe.done() {
            //
            // If the recipe is finished, restore the previous memory access permissions,
            // switch back to the default view, disable single-stepping, and restore back
            // the original registers.
            //

            let memory_access = vmi.event().reason().as_memory_access();
            let gfn = Driver::Architecture::gfn_from_pa(memory_access.pa);
            vmi.set_memory_access(gfn, self.view, MemoryAccess::RWX)?;
            vmi.monitor_disable(EventMonitor::Singlestep)?;

            vmi.switch_to_view(vmi.default_view())?;
            vmi.destroy_view(self.view)?;

            // If the bridge was not enabled, we're done.
            if !self.bridge {
                self.finished = true;
            }
        }

        Ok(VmiEventResponse::set_registers(
            new_registers.gp_registers(),
        ))
    }
}

impl<Driver, T> VmiHandler<Driver, WindowsOs<Driver>>
    for InjectorHandler<Driver, WindowsOs<Driver>, T>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    fn handle_event(
        &mut self,
        vmi: VmiContext<Driver, WindowsOs<Driver>>,
    ) -> VmiEventResponse<Amd64> {
        vmi.flush_v2p_cache();

        match self.dispatch(&vmi) {
            Ok(response) => response,
            Err(VmiError::PageFault(pfs)) => {
                let pf = pfs[0];

                tracing::warn!(?pf, "injecting page fault");
                let _ = vmi
                    .inject_interrupt(vmi.event().vcpu_id(), Interrupt::page_fault(pf.address, 0));

                VmiEventResponse::default()
            }
            Err(err) => panic!("Unhandled error: {err:?}"),
        }
    }

    fn finished(&self) -> bool {
        self.finished
    }
}
