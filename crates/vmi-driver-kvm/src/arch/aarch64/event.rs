use vmi_arch_aarch64::{
    EventBreakpoint, EventMemoryAccess, EventReason, EventSinglestep, EventSysreg, SystemRegister,
};
use vmi_core::{Gfn, Pa, Va};

use crate::TryFromExt;

impl TryFromExt<&kvm::KvmVmiEventReason> for EventReason {
    type Error = ();

    fn try_from_ext(value: &kvm::KvmVmiEventReason) -> Result<Self, Self::Error> {
        use kvm::KvmVmiEventReason;

        match *value {
            KvmVmiEventReason::MemoryAccess { gpa, access } => {
                Ok(Self::MemoryAccess(EventMemoryAccess {
                    pa: Pa(gpa),
                    va: Va(0),
                    access: vmi_core::MemoryAccess::from_bits_truncate(access as u8),
                }))
            }

            KvmVmiEventReason::Breakpoint { pc, gpa, comment } => {
                Ok(Self::Breakpoint(EventBreakpoint {
                    gfn: Gfn::new(gpa >> 12),
                    pc: Va(pc),
                    comment,
                }))
            }

            KvmVmiEventReason::Sysreg {
                reg,
                old_value,
                new_value,
            } => {
                let register = sysreg_from_index(reg)?;
                Ok(Self::Sysreg(EventSysreg {
                    register,
                    old_value,
                    new_value,
                }))
            }

            KvmVmiEventReason::Singlestep { gpa } => Ok(Self::Singlestep(EventSinglestep {
                gfn: Gfn::new(gpa >> 12),
            })),
        }
    }
}

/// Convert a KVM sysreg index to a `SystemRegister`.
fn sysreg_from_index(index: u32) -> Result<SystemRegister, ()> {
    match index {
        kvm::sys::KVM_VMI_ARM64_SYSREG_SCTLR_EL1 => Ok(SystemRegister::SctlrEl1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TTBR0_EL1 => Ok(SystemRegister::Ttbr0El1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TTBR1_EL1 => Ok(SystemRegister::Ttbr1El1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TCR_EL1 => Ok(SystemRegister::TcrEl1),
        _ => Err(()),
    }
}
