mod event;
mod registers;

use std::os::fd::RawFd;

use vmi_arch_aarch64::{Aarch64, EventMonitor, EventReason, Interrupt, SystemRegister};
use vmi_core::{
    Registers as _, VcpuId, View, VmiEvent, VmiEventAction, VmiEventFlags, VmiEventResponse,
};

use vmi_arch_aarch64::Pstate;

use crate::{ArchAdapter, Error, IntoExt as _, KvmDriver, TryFromExt};

// ARM64 KVM register ID encoding constants.
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;

/// Build a core register ID from the byte offset in `struct kvm_regs`.
const fn core_reg(offset_bytes: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (offset_bytes / 4)
}

/// Build a system register ID from the ARM64 encoding (op0, op1, CRn, CRm, op2).
const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
        | (op0 << 14)
        | (op1 << 11)
        | (crn << 7)
        | (crm << 3)
        | op2
}

// Core register IDs (offsets in struct kvm_regs / struct user_pt_regs).
// user_pt_regs: regs[31] @ 0, sp @ 248, pc @ 256, pstate @ 264.
// kvm_regs extends: sp_el1 @ 272, elr_el1 @ 280.
const REG_X0: u64 = core_reg(0);      // x[0] starts at byte 0
const REG_SP: u64 = core_reg(248);    // user_pt_regs.sp
const REG_PC: u64 = core_reg(256);    // user_pt_regs.pc (ELR_EL2)
const REG_PSTATE: u64 = core_reg(264); // user_pt_regs.pstate (SPSR_EL2)
const REG_SP_EL1: u64 = core_reg(272); // kvm_regs.sp_el1

// System register IDs.
const REG_SCTLR_EL1: u64 = sys_reg(3, 0, 1, 0, 0);
const REG_TTBR0_EL1: u64 = sys_reg(3, 0, 2, 0, 0);
const REG_TTBR1_EL1: u64 = sys_reg(3, 0, 2, 0, 1);
const REG_TCR_EL1: u64 = sys_reg(3, 0, 2, 0, 2);
const REG_ESR_EL1: u64 = sys_reg(3, 0, 5, 2, 0);
const REG_FAR_EL1: u64 = sys_reg(3, 0, 6, 0, 0);
const REG_MAIR_EL1: u64 = sys_reg(3, 0, 10, 2, 0);
const REG_CONTEXTIDR_EL1: u64 = sys_reg(3, 0, 13, 0, 1);
const REG_VBAR_EL1: u64 = sys_reg(3, 0, 12, 0, 0);
const REG_TPIDR_EL1: u64 = sys_reg(3, 0, 13, 0, 4);

/// Read a single register from a vCPU fd using KVM_GET_ONE_REG.
fn get_one_reg(vcpu_fd: RawFd, reg_id: u64) -> Result<u64, Error> {
    let mut value: u64 = 0;
    let mut one_reg = kvm::sys::kvm_one_reg {
        id: reg_id,
        addr: &mut value as *mut u64 as u64,
    };
    let ret = unsafe {
        libc::ioctl(
            vcpu_fd,
            kvm::consts::KVM_GET_ONE_REG as libc::c_ulong,
            &mut one_reg as *mut _,
        )
    };
    if ret < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(value)
}

/// Build a `kvm_vmi_control_event` for a simple event (no param union).
fn make_ctrl(event: u32, enable: u32) -> kvm::sys::kvm_vmi_control_event {
    kvm::sys::kvm_vmi_control_event {
        event,
        enable,
        flags: 0,
        pad: 0,
        __bindgen_anon_1: kvm::sys::kvm_vmi_control_event__bindgen_ty_1::default(),
    }
}

impl ArchAdapter for Aarch64 {
    fn registers_from_ring(regs: &kvm::sys::kvm_vmi_regs) -> Self::Registers {
        regs.into_ext()
    }

    fn registers_to_ring(regs: &Self::Registers) -> kvm::sys::kvm_vmi_regs {
        regs.into_ext()
    }

    fn registers_from_vcpu(vcpu_fd: RawFd) -> Result<Self::Registers, Error> {
        let mut x = [0u64; 31];
        for i in 0..31 {
            x[i] = get_one_reg(vcpu_fd, REG_X0 + (i as u64) * 2)?;
        }

        Ok(vmi_arch_aarch64::Registers {
            x,
            sp: get_one_reg(vcpu_fd, REG_SP_EL1)?,
            pc: get_one_reg(vcpu_fd, REG_PC)?,
            pstate: Pstate(get_one_reg(vcpu_fd, REG_PSTATE)?),

            sctlr_el1: get_one_reg(vcpu_fd, REG_SCTLR_EL1)?,
            ttbr0_el1: get_one_reg(vcpu_fd, REG_TTBR0_EL1)?,
            ttbr1_el1: get_one_reg(vcpu_fd, REG_TTBR1_EL1)?,
            tcr_el1: get_one_reg(vcpu_fd, REG_TCR_EL1)?,
            esr_el1: get_one_reg(vcpu_fd, REG_ESR_EL1)?,
            far_el1: get_one_reg(vcpu_fd, REG_FAR_EL1)?,
            mair_el1: get_one_reg(vcpu_fd, REG_MAIR_EL1)?,
            contextidr_el1: get_one_reg(vcpu_fd, REG_CONTEXTIDR_EL1)?,

            vbar_el1: get_one_reg(vcpu_fd, REG_VBAR_EL1)?,
            tpidr_el1: get_one_reg(vcpu_fd, REG_TPIDR_EL1)?,
            sp_el0: get_one_reg(vcpu_fd, REG_SP)?,
        })
    }

    fn monitor_enable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 1u32;

        let ctrl = match option {
            EventMonitor::Breakpoint => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_BREAKPOINT_EVAL, enable)
            }
            EventMonitor::Sysreg(_) => {
                // arm64 sysreg monitoring is controlled by HCR_EL2.TVM which
                // traps all system register writes at once.
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SYSREG_EVAL, enable)
            }
            EventMonitor::Singlestep => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable)
            }
        };

        driver.monitor.control_event(&ctrl)?;
        Ok(())
    }

    fn monitor_disable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 0u32;

        let ctrl = match option {
            EventMonitor::Breakpoint => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_BREAKPOINT_EVAL, enable)
            }
            EventMonitor::Sysreg(_) => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SYSREG_EVAL, enable)
            }
            EventMonitor::Singlestep => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable)
            }
        };

        let _ = driver.monitor.control_event(&ctrl);
        Ok(())
    }

    fn inject_interrupt(
        driver: &KvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Interrupt,
    ) -> Result<(), Error> {
        let (typ, esr) = match interrupt {
            Interrupt::Sync(exc) => (kvm::sys::KVM_VMI_ARM64_INJECT_SYNC, exc.to_esr()),
            Interrupt::SError { iss } => (kvm::sys::KVM_VMI_ARM64_INJECT_SERROR, iss as u64),
        };
        Ok(driver
            .session
            .inject_event(u16::from(vcpu) as u32, typ, esr)?)
    }

    fn process_event(
        _driver: &KvmDriver<Self>,
        raw_event: &mut kvm::sys::kvm_vmi_ring_event,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error> {
        // Parse the raw ring event into a safe event.
        let kvm_event =
            unsafe { kvm::KvmVmiEvent::from_raw(raw_event) }.ok_or(Error::NotSupported)?;

        // Convert to VMI event reason.
        let vmi_reason =
            EventReason::try_from_ext(&kvm_event.reason).map_err(|()| Error::NotSupported)?;

        // Convert registers.
        let mut registers = Self::registers_from_ring(&raw_event.regs);

        // Build the VMI event.
        let view = Some(View(kvm_event.view_id as u16));
        let flags = VmiEventFlags::VCPU_PAUSED;
        let vcpu_id = VcpuId::from(kvm_event.vcpu_id as u16);

        let vmi_event = VmiEvent::new(vcpu_id, flags, view, registers, vmi_reason);

        // Call the user's handler.
        let vmi_response = handler(&vmi_event);

        // Build the ring response flags.
        let mut response_flags: u32 = kvm::sys::KVM_VMI_RESPONSE_CONTINUE;

        // Handle SET_REGS.
        if let Some(new_gp_regs) = &vmi_response.registers {
            registers.set_gp_registers(new_gp_regs);
            raw_event.regs = Self::registers_to_ring(&registers);
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SET_REGS;
        }

        // Handle SWITCH_VIEW.
        if let Some(new_view) = vmi_response.view {
            raw_event.view_id = new_view.0 as u32;
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
        }

        // Map VmiEventAction to KVM response flags.
        match vmi_response.action {
            VmiEventAction::Continue => {}
            VmiEventAction::Deny => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_DENY;
            }
            VmiEventAction::ReinjectInterrupt => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_REINJECT;
            }
            VmiEventAction::Singlestep => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP;
            }
            VmiEventAction::FastSinglestep => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP_FAST;
            }
            VmiEventAction::Emulate => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_EMULATE;
            }
        }

        raw_event.response = response_flags;

        Ok(())
    }

    fn reset_state(driver: &KvmDriver<Self>) -> Result<(), Error> {
        let _ = driver.monitor_disable(EventMonitor::Breakpoint);
        let _ = driver.monitor_disable(EventMonitor::Sysreg(SystemRegister::SctlrEl1));
        let _ = driver.monitor_disable(EventMonitor::Singlestep);
        let _ = driver.monitor.control_event(&make_ctrl(
            kvm::sys::KVM_VMI_EVENT_MEM_ACCESS,
            0,
        ));

        // Switch all vCPUs back to view 0.
        let _ = driver.session.switch_view(0);

        // Destroy all views.
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
