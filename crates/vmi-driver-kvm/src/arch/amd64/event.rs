//! Event-reason construction and response translation for amd64 KVM events.

use kvm::{
    KvmEventReason, KvmVmiEvent,
    arch::x86::{
        KvmCpuidEvent, KvmCr, KvmCrEvent, KvmDebugEvent, KvmEventReasonX86, KvmIoEvent, KvmMsrEvent,
    },
};
use vmi_arch_amd64::{
    Amd64, ControlRegister, EventCpuId, EventHypercall, EventInterrupt, EventIo, EventIoDirection,
    EventMemoryAccess, EventReason, EventSinglestep, EventWriteCr, EventWriteMsr, ExceptionVector,
    Interrupt, InterruptType, MemoryAccessFlags,
};
use vmi_core::{Architecture, MemoryAccess, Pa, Va, VmiError};

use crate::convert::FromExt;

impl FromExt<KvmCrEvent> for EventWriteCr {
    fn from_ext(value: KvmCrEvent) -> Self {
        let register = match value.index {
            KvmCr::Cr0 => ControlRegister::Cr0,
            KvmCr::Cr3 => ControlRegister::Cr3,
            KvmCr::Cr4 => ControlRegister::Cr4,
            KvmCr::Xcr0 => ControlRegister::Xcr0,
        };
        Self {
            register,
            new_value: value.new,
            old_value: value.old,
        }
    }
}

impl FromExt<KvmMsrEvent> for EventWriteMsr {
    fn from_ext(value: KvmMsrEvent) -> Self {
        Self {
            register: value.index,
            new_value: value.new,
            old_value: value.old,
        }
    }
}

impl FromExt<KvmCpuidEvent> for EventCpuId {
    fn from_ext(value: KvmCpuidEvent) -> Self {
        Self {
            leaf: value.leaf,
            subleaf: value.subleaf,
            instruction_length: 0,
        }
    }
}

impl FromExt<KvmIoEvent> for EventIo {
    fn from_ext(value: KvmIoEvent) -> Self {
        Self {
            port: value.port,
            length: u32::from(value.bytes),
            direction: if value.in_ {
                EventIoDirection::In
            }
            else {
                EventIoDirection::Out
            },
            string: value.string,
        }
    }
}

/// Builds an `EventReason` for a breakpoint event. The breakpoint GPA gives the
/// GFN of the faulting instruction.
fn breakpoint_reason(gpa: u64, insn_len: u8) -> EventReason {
    EventReason::Interrupt(EventInterrupt {
        gfn: Amd64::gfn_from_pa(Pa::new(gpa)),
        interrupt: Interrupt {
            vector: ExceptionVector::Breakpoint,
            typ: InterruptType::SoftwareException,
            error_code: 0xffff_ffff,
            instruction_length: insn_len,
            extra: 0,
        },
    })
}

/// Builds an `EventReason` for a debug exception. The pending_dbg value carries
/// DR6/pending-debug state.
fn debug_reason(value: KvmDebugEvent, insn_len: u8) -> EventReason {
    EventReason::Interrupt(EventInterrupt {
        gfn: Amd64::gfn_from_pa(Pa::new(value.gpa)),
        interrupt: Interrupt {
            vector: ExceptionVector::DebugException,
            typ: InterruptType::HardwareException,
            error_code: 0xffff_ffff,
            instruction_length: insn_len,
            extra: value.pending_dbg,
        },
    })
}

/// Converts a decoded KVM event into the architecture event reason.
pub(super) fn reason_from_event(ev: &KvmVmiEvent) -> Result<EventReason, VmiError> {
    match ev.reason {
        KvmEventReason::MemAccess(m) => Ok(EventReason::MemoryAccess(EventMemoryAccess {
            pa: Pa::new(m.gpa),
            va: Va::default(),
            access: MemoryAccess::from_ext(m.access),
            flags: MemoryAccessFlags::default(),
        })),
        KvmEventReason::Singlestep(ss) => Ok(EventReason::Singlestep(EventSinglestep {
            gfn: Amd64::gfn_from_pa(Pa::new(ss.gpa)),
        })),
        KvmEventReason::Hypercall => Ok(EventReason::Hypercall(EventHypercall {
            // VMCALL is always 3 bytes: 0F 01 C1.
            instruction_length: 3,
        })),
        KvmEventReason::Arch(KvmEventReasonX86::WriteCr(cr)) => {
            Ok(EventReason::WriteCr(EventWriteCr::from_ext(cr)))
        }
        KvmEventReason::Arch(KvmEventReasonX86::WriteMsr(msr)) => {
            Ok(EventReason::WriteMsr(EventWriteMsr::from_ext(msr)))
        }
        KvmEventReason::Arch(KvmEventReasonX86::CpuId(c)) => {
            let mut event = EventCpuId::from_ext(c);
            event.instruction_length = ev.insn_len;
            Ok(EventReason::CpuId(event))
        }
        KvmEventReason::Arch(KvmEventReasonX86::Breakpoint(bp)) => {
            Ok(breakpoint_reason(bp.gpa, ev.insn_len))
        }
        KvmEventReason::Arch(KvmEventReasonX86::Debug(d)) => Ok(debug_reason(d, ev.insn_len)),
        KvmEventReason::Arch(KvmEventReasonX86::Io(io)) => {
            Ok(EventReason::Io(EventIo::from_ext(io)))
        }
    }
}
