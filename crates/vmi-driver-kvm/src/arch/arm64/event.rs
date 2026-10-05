//! Event-reason construction for arm64 KVM events.

use kvm::{KvmEventReason, KvmVmiEvent, arch::arm64::KvmEventReasonArm64};
use vmi_arch_arm64::{
    Arm64, EventInterrupt, EventMemoryAccess, EventReason, EventSinglestep,
    EventWriteSystemRegister, Interrupt, PagingGeometry,
};
use vmi_core::{Architecture as _, MemoryAccess, Pa, Va, VmiError};

use crate::convert::FromExt;

/// Converts a decoded KVM event into the arm64 event reason.
pub(super) fn reason_from_event<Geometry>(
    event: &KvmVmiEvent,
) -> Result<EventReason<Geometry>, VmiError>
where
    Geometry: PagingGeometry,
{
    match event.reason {
        // The kernel reports only the guest-physical address of the access.
        KvmEventReason::MemAccess(memory_access) => {
            Ok(EventReason::MemoryAccess(EventMemoryAccess::new(
                Pa(memory_access.gpa),
                Va(0),
                MemoryAccess::from_ext(memory_access.access),
            )))
        }

        // The kernel payload (gpa) is intentionally dropped. Handlers read the
        // stepped instruction's address from the registers.
        KvmEventReason::Singlestep(_) => Ok(EventReason::Singlestep(EventSinglestep)),

        KvmEventReason::Hypercall => Err(VmiError::NotSupported),

        KvmEventReason::Arch(KvmEventReasonArm64::Breakpoint(breakpoint)) => {
            Ok(EventReason::Interrupt(EventInterrupt::new(
                Arm64::<Geometry>::gfn_from_pa(Pa(breakpoint.gpa)),
                Interrupt::software_breakpoint(breakpoint.imm),
            )))
        }

        KvmEventReason::Arch(KvmEventReasonArm64::Sysreg(sysreg)) => {
            let register = match super::system_register(sysreg.reg) {
                Some(register) => register,
                None => return Err(VmiError::NotSupported),
            };

            Ok(EventReason::WriteSystemRegister(EventWriteSystemRegister {
                register,
                new_value: sysreg.new_value,
                old_value: sysreg.old_value,
            }))
        }
    }
}
