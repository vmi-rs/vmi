use vmi_arch_amd64::{
    ControlRegister, EventCpuId, EventInterrupt, EventIo, EventIoDirection, EventMemoryAccess,
    EventReason, EventSinglestep, EventWriteControlRegister, ExceptionVector, Interrupt,
    InterruptType, MemoryAccessFlags,
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
                    flags: MemoryAccessFlags::empty(),
                }))
            }

            KvmVmiEventReason::Cr {
                index,
                old_value,
                new_value,
            } => {
                let register = cr_from_index(index)?;
                Ok(Self::WriteControlRegister(EventWriteControlRegister {
                    register,
                    new_value,
                    old_value,
                }))
            }

            KvmVmiEventReason::Breakpoint { gpa, insn_len } => {
                Ok(Self::Interrupt(EventInterrupt {
                    gfn: Gfn::new(gpa / 0x1000),
                    interrupt: Interrupt {
                        vector: ExceptionVector::Breakpoint,
                        typ: InterruptType::SoftwareException,
                        error_code: 0xffff_ffff,
                        instruction_length: insn_len as u8,
                        extra: 0,
                    },
                }))
            }

            KvmVmiEventReason::Singlestep { gpa } => Ok(Self::Singlestep(EventSinglestep {
                gfn: Gfn::new(gpa / 0x1000),
            })),

            KvmVmiEventReason::Debug { pending_dbg } => Ok(Self::Interrupt(EventInterrupt {
                gfn: Gfn::new(0),
                interrupt: Interrupt {
                    vector: ExceptionVector::DebugException,
                    typ: InterruptType::HardwareException,
                    error_code: 0xffff_ffff,
                    instruction_length: 0,
                    extra: pending_dbg,
                },
            })),

            KvmVmiEventReason::Cpuid { leaf, subleaf } => Ok(Self::CpuId(EventCpuId {
                leaf,
                subleaf,
                instruction_length: 2, // CPUID is 0F A2 = 2 bytes
            })),

            KvmVmiEventReason::Io {
                port,
                bytes,
                direction,
                string,
            } => Ok(Self::Io(EventIo {
                port,
                length: bytes as u32,
                direction: if direction != 0 {
                    EventIoDirection::In
                } else {
                    EventIoDirection::Out
                },
                string,
            })),

            // MSR, DescAccess, Interrupt events don't have direct EventReason equivalents.
            KvmVmiEventReason::Msr { .. }
            | KvmVmiEventReason::DescAccess { .. }
            | KvmVmiEventReason::Interrupt { .. } => Err(()),
        }
    }
}

/// Convert a KVM CR index to a `ControlRegister`.
fn cr_from_index(index: u32) -> Result<ControlRegister, ()> {
    match index {
        kvm::sys::KVM_VMI_CR0 => Ok(ControlRegister::Cr0),
        kvm::sys::KVM_VMI_CR3 => Ok(ControlRegister::Cr3),
        kvm::sys::KVM_VMI_CR4 => Ok(ControlRegister::Cr4),
        kvm::sys::KVM_VMI_XCR0 => Ok(ControlRegister::Xcr0),
        _ => Err(()),
    }
}

/// Convert a `ControlRegister` to a KVM CR index.
pub(crate) fn cr_to_index(cr: ControlRegister) -> u8 {
    match cr {
        ControlRegister::Cr0 => kvm::sys::KVM_VMI_CR0 as u8,
        ControlRegister::Cr3 => kvm::sys::KVM_VMI_CR3 as u8,
        ControlRegister::Cr4 => kvm::sys::KVM_VMI_CR4 as u8,
        ControlRegister::Xcr0 => kvm::sys::KVM_VMI_XCR0 as u8,
    }
}

/// Convert an `InterruptType` to a KVM event type value.
pub(crate) fn interrupt_type_to_kvm(typ: InterruptType) -> u8 {
    match typ {
        InterruptType::ExternalInterrupt => kvm::sys::KVM_VMI_EVENT_TYPE_EXT_INT as u8,
        InterruptType::Nmi => kvm::sys::KVM_VMI_EVENT_TYPE_NMI as u8,
        InterruptType::HardwareException => kvm::sys::KVM_VMI_EVENT_TYPE_HW_EXCEPT as u8,
        InterruptType::SoftwareInterrupt => kvm::sys::KVM_VMI_EVENT_TYPE_SW_INT as u8,
        InterruptType::PrivilegedSoftwareException => {
            kvm::sys::KVM_VMI_EVENT_TYPE_PRIV_SW_INT as u8
        }
        InterruptType::SoftwareException => kvm::sys::KVM_VMI_EVENT_TYPE_SW_EXCEPT as u8,
        InterruptType::Reserved => 1, // reserved type
    }
}
