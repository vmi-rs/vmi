use vmi_arch_amd64::{
    Amd64, ControlRegister, EventCpuId, EventInterrupt, EventIo, EventIoDirection,
    EventMemoryAccess, EventReason, EventSinglestep, EventWriteControlRegister, ExceptionVector,
    Interrupt, InterruptType, MemoryAccessFlags,
};
use xen::{
    ctrl::{
        VmEventCpuid, VmEventCtrlReg, VmEventDebug, VmEventIo, VmEventMemAccess, VmEventReason,
        VmEventSinglestep, VmEventWriteCtrlReg,
    },
    XenX86EventType, XenX86ExceptionVector,
};

use crate::{Architecture as _, FromExt, Gfn, IntoExt, MemoryAccess, TryFromExt};

impl FromExt<&VmEventMemAccess> for EventMemoryAccess {
    fn from_ext(value: &VmEventMemAccess) -> Self {
        Self {
            pa: Amd64::pa_from_gfn(Gfn::new(value.gfn)) + value.offset,
            va: value.gla.into(),
            access: MemoryAccess::from_bits_truncate(value.flags as u8),
            flags: MemoryAccessFlags::from_bits_truncate(value.flags as u8),
        }
    }
}

impl FromExt<ControlRegister> for VmEventCtrlReg {
    fn from_ext(value: ControlRegister) -> Self {
        match value {
            ControlRegister::Cr0 => Self::Cr0,
            ControlRegister::Cr3 => Self::Cr3,
            ControlRegister::Cr4 => Self::Cr4,
            ControlRegister::Xcr0 => Self::Xcr0,
        }
    }
}

impl FromExt<VmEventCtrlReg> for ControlRegister {
    fn from_ext(value: VmEventCtrlReg) -> Self {
        match value {
            VmEventCtrlReg::Cr0 => Self::Cr0,
            VmEventCtrlReg::Cr3 => Self::Cr3,
            VmEventCtrlReg::Cr4 => Self::Cr4,
            VmEventCtrlReg::Xcr0 => Self::Xcr0,
        }
    }
}

impl FromExt<&VmEventWriteCtrlReg> for EventWriteControlRegister {
    fn from_ext(value: &VmEventWriteCtrlReg) -> Self {
        Self {
            register: value.index.into_ext(),
            new_value: value.new_value,
            old_value: value.old_value,
        }
    }
}

impl FromExt<InterruptType> for XenX86EventType {
    fn from_ext(value: InterruptType) -> Self {
        use InterruptType::*;
        match value {
            ExternalInterrupt => Self::ExternalInterrupt,
            Reserved => Self::Reserved,
            Nmi => Self::Nmi,
            HardwareException => Self::HardwareException,
            SoftwareInterrupt => Self::SoftwareInterrupt,
            PrivilegedSoftwareException => Self::PrivilegedSoftwareException,
            SoftwareException => Self::SoftwareException,
        }
    }
}

impl FromExt<XenX86EventType> for InterruptType {
    fn from_ext(value: XenX86EventType) -> Self {
        use XenX86EventType::*;
        match value {
            ExternalInterrupt => Self::ExternalInterrupt,
            Reserved => Self::Reserved,
            Nmi => Self::Nmi,
            HardwareException => Self::HardwareException,
            SoftwareInterrupt => Self::SoftwareInterrupt,
            PrivilegedSoftwareException => Self::PrivilegedSoftwareException,
            SoftwareException => Self::SoftwareException,
        }
    }
}

impl FromExt<ExceptionVector> for XenX86ExceptionVector {
    fn from_ext(value: ExceptionVector) -> Self {
        use ExceptionVector::*;
        match value {
            DivideError => Self::DivideError,
            DebugException => Self::DebugException,
            Nmi => Self::Nmi,
            Breakpoint => Self::Breakpoint,
            Overflow => Self::Overflow,
            BoundRange => Self::BoundRange,
            InvalidOpcode => Self::InvalidOpcode,
            DeviceNotAvailable => Self::DeviceNotAvailable,
            DoubleFault => Self::DoubleFault,
            CoprocessorSegmentOverrun => Self::CoprocessorSegmentOverrun,
            InvalidTss => Self::InvalidTss,
            SegmentNotPresent => Self::SegmentNotPresent,
            StackSegmentFault => Self::StackSegmentFault,
            GeneralProtectionFault => Self::GeneralProtectionFault,
            PageFault => Self::PageFault,
            PicSpuriousInterruptVector => Self::PicSpuriousInterruptVector,
            MathsFault => Self::MathsFault,
            AlignmentCheck => Self::AlignmentCheck,
            MachineCheck => Self::MachineCheck,
            SimdException => Self::SimdException,
            VirtualisationException => Self::VirtualisationException,
            ControlFlowProtection => Self::ControlFlowProtection,
            //HypervisorInjection => Self::HypervisorInjection,
            //VmmCommunication => Self::VmmCommunication,
            //SecurityException => Self::SecurityException,
        }
    }
}

impl FromExt<(&VmEventDebug, ExceptionVector)> for EventInterrupt {
    fn from_ext(value: (&VmEventDebug, ExceptionVector)) -> Self {
        Self {
            gfn: Gfn::new(value.0.gfn),
            interrupt: Interrupt {
                vector: value.1,
                typ: value.0.typ.into_ext(),
                error_code: 0xffff_ffff,
                instruction_length: value.0.insn_length as u8,
                extra: value.0.pending_dbg,
            },
        }
    }
}

impl FromExt<&VmEventSinglestep> for EventSinglestep {
    fn from_ext(value: &VmEventSinglestep) -> Self {
        Self {
            gfn: Gfn::new(value.gfn),
        }
    }
}

impl FromExt<&VmEventCpuid> for EventCpuId {
    fn from_ext(value: &VmEventCpuid) -> Self {
        Self {
            leaf: value.leaf,
            subleaf: value.subleaf,
            instruction_length: value.insn_length as u8,
        }
    }
}

impl FromExt<&VmEventIo> for EventIo {
    fn from_ext(value: &VmEventIo) -> Self {
        Self {
            port: value.port,
            length: value.bytes,
            direction: match value.direction {
                0 => EventIoDirection::Out,
                1 => EventIoDirection::In,
                _ => unreachable!(),
            },
            string: value.str != 0,
        }
    }
}

impl TryFromExt<&VmEventReason> for EventReason {
    type Error = ();

    fn try_from_ext(value: &VmEventReason) -> Result<Self, Self::Error> {
        use VmEventReason::*;
        match value {
            MemoryAccess(value) => Ok(Self::MemoryAccess(value.into_ext())),
            WriteCtrlReg(value) => Ok(Self::WriteControlRegister(value.into_ext())),
            SoftwareBreakpoint(value) => Ok(Self::Interrupt(
                (value, ExceptionVector::Breakpoint).into_ext(),
            )),
            DebugException(value) => Ok(Self::Interrupt(
                (value, ExceptionVector::DebugException).into_ext(),
            )),
            Singlestep(value) => Ok(Self::Singlestep(value.into_ext())),
            Cpuid(value) => Ok(Self::CpuId(value.into_ext())),
            IoInstruction(value) => Ok(Self::Io(value.into_ext())),
            _ => Err(()),
        }
    }
}
