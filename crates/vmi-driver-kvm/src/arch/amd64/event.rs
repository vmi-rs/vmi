//! Event-reason construction and response translation for amd64 KVM events.

use vmi_arch_amd64::{
    ControlRegister, EventCpuId, EventHypercall, EventInterrupt, EventIo, EventIoDirection,
    EventMemoryAccess, EventReason, EventSinglestep, EventWriteCr, EventWriteMsr, ExceptionVector,
    Interrupt, InterruptType, MemoryAccessFlags,
};
use vmi_core::{Gfn, MemoryAccess, Pa, Va, VmiError};

use crate::convert::FromExt;

/// Maps a KVM control-register index to the amd64 `ControlRegister`.
fn control_register_from_index(index: u32) -> Result<ControlRegister, VmiError> {
    if index == kvm::sys::KVM_VMI_CR0 {
        Ok(ControlRegister::Cr0)
    }
    else if index == kvm::sys::KVM_VMI_CR3 {
        Ok(ControlRegister::Cr3)
    }
    else if index == kvm::sys::KVM_VMI_CR4 {
        Ok(ControlRegister::Cr4)
    }
    else if index == kvm::sys::KVM_VMI_XCR0 {
        Ok(ControlRegister::Xcr0)
    }
    else {
        Err(VmiError::NotSupported)
    }
}

impl FromExt<&kvm::sys::kvm_vmi_event_cr> for EventWriteCr {
    fn from_ext(value: &kvm::sys::kvm_vmi_event_cr) -> Self {
        Self {
            // The kernel only delivers CR write events for indices the agent
            // explicitly enabled, all of which map in control_register_from_index,
            // so the Cr0 fallback is unreachable. The FromExt signature is
            // infallible, hence the unwrap_or rather than propagating an error.
            register: control_register_from_index(value.index).unwrap_or(ControlRegister::Cr0),
            new_value: value.new_value,
            old_value: value.old_value,
        }
    }
}

impl FromExt<&kvm::sys::kvm_vmi_event_msr> for EventWriteMsr {
    fn from_ext(value: &kvm::sys::kvm_vmi_event_msr) -> Self {
        Self {
            register: value.index,
            new_value: value.new_value,
            old_value: value.old_value,
        }
    }
}

impl FromExt<&kvm::sys::kvm_vmi_event_cpuid> for EventCpuId {
    fn from_ext(value: &kvm::sys::kvm_vmi_event_cpuid) -> Self {
        Self {
            leaf: value.leaf,
            subleaf: value.subleaf,
            instruction_length: 0,
        }
    }
}

impl FromExt<&kvm::sys::kvm_vmi_event_io> for EventIo {
    fn from_ext(value: &kvm::sys::kvm_vmi_event_io) -> Self {
        Self {
            port: value.port,
            length: u32::from(value.bytes),
            direction: if value.in_ != 0 {
                EventIoDirection::In
            }
            else {
                EventIoDirection::Out
            },
            string: value.string != 0,
        }
    }
}

/// Builds an `EventReason` from a ring slot for a breakpoint event. The
/// breakpoint GPA gives the GFN of the faulting instruction.
fn breakpoint_reason(gpa: u64, insn_len: u8) -> EventReason {
    EventReason::Interrupt(EventInterrupt {
        gfn: Gfn::new(gpa >> 12),
        interrupt: Interrupt {
            vector: ExceptionVector::Breakpoint,
            typ: InterruptType::SoftwareException,
            error_code: 0xffff_ffff,
            instruction_length: insn_len,
            extra: 0,
        },
    })
}

/// Builds an `EventReason` from a ring slot for a debug exception. The
/// pending_dbg value carries DR6/pending-debug state.
fn debug_reason(value: &kvm::sys::kvm_vmi_event_debug, insn_len: u8) -> EventReason {
    EventReason::Interrupt(EventInterrupt {
        gfn: Gfn::new(value.gpa >> 12),
        interrupt: Interrupt {
            vector: ExceptionVector::DebugException,
            typ: InterruptType::HardwareException,
            error_code: 0xffff_ffff,
            instruction_length: insn_len,
            extra: value.pending_dbg,
        },
    })
}

/// Converts a ring event slot into the architecture event reason.
pub(super) fn reason_from_slot(
    slot: &kvm::sys::kvm_vmi_ring_event,
) -> Result<EventReason, VmiError> {
    let kind = slot.type_;
    let insn_len = slot.insn_len;

    if kind == kvm::sys::KVM_VMI_EVENT_MEM_ACCESS {
        // SAFETY: type_ selects the mem_access arm of the event union.
        let mem = unsafe { slot.__bindgen_anon_1.mem_access };
        Ok(EventReason::MemoryAccess(EventMemoryAccess {
            pa: Pa::new(mem.gpa),
            va: Va::default(),
            access: MemoryAccess::from_ext(mem.access as u8),
            flags: MemoryAccessFlags::default(),
        }))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_CR {
        // SAFETY: type_ selects the cr arm of the arch event union.
        let cr = unsafe { slot.__bindgen_anon_1.arch.cr };
        Ok(EventReason::WriteCr(EventWriteCr::from_ext(&cr)))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_MSR {
        // SAFETY: type_ selects the msr arm of the arch event union.
        let msr = unsafe { slot.__bindgen_anon_1.arch.msr };
        Ok(EventReason::WriteMsr(EventWriteMsr::from_ext(&msr)))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_CPUID {
        // SAFETY: type_ selects the cpuid arm of the arch event union.
        let cpuid = unsafe { slot.__bindgen_anon_1.arch.cpuid };
        let mut event = EventCpuId::from_ext(&cpuid);
        event.instruction_length = insn_len;
        Ok(EventReason::CpuId(event))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_BREAKPOINT {
        // SAFETY: type_ selects the breakpoint arm of the arch event union.
        let bp = unsafe { slot.__bindgen_anon_1.arch.breakpoint };
        Ok(breakpoint_reason(bp.gpa, insn_len))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_DEBUG {
        // SAFETY: type_ selects the debug arm of the arch event union.
        let debug = unsafe { slot.__bindgen_anon_1.arch.debug };
        Ok(debug_reason(&debug, insn_len))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_IO {
        // SAFETY: type_ selects the io arm of the arch event union.
        let io = unsafe { slot.__bindgen_anon_1.arch.io };
        Ok(EventReason::Io(EventIo::from_ext(&io)))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_SINGLESTEP {
        // SAFETY: type_ selects the singlestep arm of the event union.
        let ss = unsafe { slot.__bindgen_anon_1.singlestep };
        Ok(EventReason::Singlestep(EventSinglestep {
            gfn: Gfn::new(ss.gpa >> 12),
        }))
    }
    else if kind == kvm::sys::KVM_VMI_EVENT_HYPERCALL {
        Ok(EventReason::Hypercall(EventHypercall {
            // VMCALL is always 3 bytes: 0F 01 C1.
            instruction_length: 3,
        }))
    }
    else {
        Err(VmiError::NotSupported)
    }
}
