//! Event-reason construction for arm64 KVM events.

use kvm::{
    KvmEventReason, KvmVmiEvent,
    arch::arm64::{KvmBreakpointEvent, KvmEventReasonArm64},
};
use vmi_arch_arm64::{
    Arm64, EventInterrupt, EventMemoryAccess, EventReason, EventSinglestep,
    EventWriteSystemRegister, Interrupt, InterruptType, SystemRegister,
};
use vmi_core::{Architecture, MemoryAccess, Pa, VmiError};

use crate::convert::FromExt;

/// Builds an `EventReason` for a software-breakpoint event.
///
/// Wraps the faulting GPA as a synchronous interrupt with a zero ESR,
/// matching the minimal information the in-event breakpoint payload carries.
fn breakpoint_reason(bp: KvmBreakpointEvent) -> EventReason {
    EventReason::Interrupt(EventInterrupt {
        gfn: Arm64::gfn_from_pa(Pa::new(bp.gpa)),
        interrupt: Interrupt {
            typ: InterruptType::Synchronous,
            esr: 0,
            far: 0,
            fsc: 0,
            write: false,
        },
    })
}

/// Converts a decoded KVM event into the arm64 event reason.
pub(super) fn reason_from_event(ev: &KvmVmiEvent) -> Result<EventReason, VmiError> {
    match ev.reason {
        KvmEventReason::MemAccess(m) => Ok(EventReason::MemoryAccess(EventMemoryAccess {
            pa: Pa::new(m.gpa),
            va: Default::default(),
            access: MemoryAccess::from_ext(m.access),
        })),
        // The kernel payload (gpa) is intentionally dropped. Handlers
        // read the stepped instruction's address from the registers.
        KvmEventReason::Singlestep(_) => Ok(EventReason::Singlestep(EventSinglestep)),
        KvmEventReason::Hypercall => {
            // HVC is always 4 bytes on AArch64.
            Err(VmiError::NotSupported)
        }
        KvmEventReason::Arch(KvmEventReasonArm64::Breakpoint(bp)) => Ok(breakpoint_reason(bp)),
        KvmEventReason::Arch(KvmEventReasonArm64::Sysreg(sr)) => {
            let register =
                SystemRegister::from_kvm_index(sr.reg as u32).ok_or(VmiError::NotSupported)?;
            Ok(EventReason::WriteSystemRegister(EventWriteSystemRegister {
                register,
                old_value: sr.old_value,
                new_value: sr.new_value,
            }))
        }
    }
}
