use vmi_core::{Gfn, MemoryAccess, Pa, Va};

use crate::{ControlRegister, ExceptionVector, Interrupt};

bitflags::bitflags! {
    /// Flags describing a memory access event.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryAccessFlags: u8 {
        /// The [`EventMemoryAccess::va`] field holds a guest VA associated with the event.
        const GLA_VALID        = (1 << 3);

        /// The `MemoryAccess` event was triggered by accessing a guest linear address.
        const FAULT_WITH_GLA   = (1 << 4);

        /// The `MemoryAccess` event was triggered during translating a guest linear address.
        const FAULT_IN_GPT     = (1 << 5);
    }
}

/// Event generated when monitored memory is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess {
    /// Physical address that was accessed.
    pub pa: Pa,

    /// Virtual address that was accessed.
    pub va: Va,

    /// Type of access that occurred (read/write/execute).
    pub access: MemoryAccess,

    /// Additional flags describing the access.
    pub flags: MemoryAccessFlags,
}

/// Event generated when a control register is written to.
#[derive(Debug, Clone, Copy)]
pub struct EventWriteControlRegister {
    /// The control register that was written to (CR0, CR3, CR4 or XCR0).
    pub register: ControlRegister,

    /// New value of the control register.
    pub new_value: u64,

    /// Old value of the control register.
    pub old_value: u64,
}

/// Event generated when an interrupt or exception occurs.
#[derive(Debug, Clone, Copy)]
pub struct EventInterrupt {
    /// GFN of the instruction that caused the interrupt.
    /// Effectively, this is GFN of the current instruction pointer.
    pub gfn: Gfn,

    /// Information about the interrupt/exception.
    pub interrupt: Interrupt,
}

/// Event generated when a singlestep event occurs.
#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep {
    /// GFN of the instruction that caused the singlestep.
    pub gfn: Gfn,
}

/// Event generated when a CPUID instruction is executed.
#[derive(Debug, Clone, Copy)]
pub struct EventCpuId {
    /// CPUID leaf (EAX).
    pub leaf: u32,

    /// CPUID subleaf (ECX).
    pub subleaf: u32,

    /// Length of the CPUID instruction.
    pub instruction_length: u8,
}

/// Direction of the I/O port access.
#[derive(Debug, Clone, Copy)]
pub enum EventIoDirection {
    /// I/O port read.
    In,

    /// I/O port write.
    Out,
}

/// Event generated when an I/O port is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventIo {
    /// I/O port that was accessed.
    pub port: u16,

    /// Number of bytes transferred.
    pub length: u32,

    /// Direction of transfer (in/out).
    pub direction: EventIoDirection,

    /// True for string I/O instructions (INS/OUTS).
    pub string: bool,
}

/// Reason for an event.
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    /// Memory access event (read/write/execute).
    MemoryAccess(EventMemoryAccess),

    /// Control register write event.
    WriteControlRegister(EventWriteControlRegister),

    /// Interrupt or exception event.
    Interrupt(EventInterrupt),

    /// Singlestep event.
    Singlestep(EventSinglestep),

    /// CPUID instruction event.
    CpuId(EventCpuId),

    /// I/O port access event.
    Io(EventIo),
}

impl EventReason {
    /// Returns the memory access event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a memory access event.
    pub fn as_memory_access(&self) -> &EventMemoryAccess {
        match self {
            Self::MemoryAccess(memory_access) => memory_access,
            _ => panic!("EventReason is not a MemoryAccess"),
        }
    }

    /// Returns the control register write event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a control register write event.
    pub fn as_write_control_register(&self) -> &EventWriteControlRegister {
        match self {
            Self::WriteControlRegister(write_control_register) => write_control_register,
            _ => panic!("EventReason is not a WriteControlRegister"),
        }
    }

    /// Returns the interrupt or exception event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not an interrupt or exception event.
    pub fn as_interrupt(&self) -> &EventInterrupt {
        match self {
            Self::Interrupt(interrupt) => interrupt,
            _ => panic!("EventReason is not an Interrupt"),
        }
    }

    /// Returns the singlestep event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a singlestep event.
    pub fn as_singlestep(&self) -> &EventSinglestep {
        match self {
            Self::Singlestep(singlestep) => singlestep,
            _ => panic!("EventReason is not a Singlestep"),
        }
    }

    /// Returns the CPUID instruction event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a CPUID instruction event.
    pub fn as_cpuid(&self) -> &EventCpuId {
        match self {
            Self::CpuId(cpuid) => cpuid,
            _ => panic!("EventReason is not a CpuId"),
        }
    }

    /// Returns the I/O port access event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not an I/O port access event.
    pub fn as_io(&self) -> &EventIo {
        match self {
            Self::Io(io) => io,
            _ => panic!("EventReason is not an Io"),
        }
    }
}

/// Specifies which hardware events should be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    // MemoryAccess, (implicit)
    /// Monitor writes to a specific control register.
    Register(ControlRegister),

    /// Monitor specific hardware interrupts or exception vectors.
    Interrupt(ExceptionVector),

    /// Monitor singlestep execution of instructions.
    Singlestep,

    /// Monitor execution of CPUID instructions.
    CpuId,

    /// Monitor I/O port accesses.
    Io,
}
