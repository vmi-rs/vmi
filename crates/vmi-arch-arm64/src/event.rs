use vmi_core::{Gfn, MemoryAccess, Pa, Va};

use crate::Interrupt;

/// Event generated when monitored memory is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess<Geometry> {
    /// Physical address that was accessed.
    pub pa: Pa,

    /// Virtual address that was accessed.
    pub va: Va,

    /// Type of access that occurred.
    pub access: MemoryAccess,

    _geometry: std::marker::PhantomData<Geometry>,
}

impl<Geometry> EventMemoryAccess<Geometry> {
    /// Creates a memory access event.
    pub fn new(pa: Pa, va: Va, access: MemoryAccess) -> Self {
        Self {
            pa,
            va,
            access,
            _geometry: std::marker::PhantomData,
        }
    }
}

/// Event generated when an interrupt or exception occurs.
#[derive(Debug, Clone, Copy)]
pub struct EventInterrupt<Geometry> {
    /// GFN of the instruction that raised the interrupt.
    pub gfn: Gfn,

    /// Information about the interrupt or exception.
    pub interrupt: Interrupt,

    _geometry: std::marker::PhantomData<Geometry>,
}

impl<Geometry> EventInterrupt<Geometry> {
    /// Creates an interrupt event.
    pub fn new(gfn: Gfn, interrupt: Interrupt) -> Self {
        Self {
            gfn,
            interrupt,
            _geometry: std::marker::PhantomData,
        }
    }
}

/// EL1 system register whose writes can be monitored.
///
/// The set covers the virtual memory control registers that a hypervisor can
/// trap with `HCR_EL2.TVM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    /// System control register (`SCTLR_EL1`).
    SctlrEl1,

    /// User translation table base register (`TTBR0_EL1`).
    Ttbr0El1,

    /// Kernel translation table base register (`TTBR1_EL1`).
    Ttbr1El1,

    /// Translation control register (`TCR_EL1`).
    TcrEl1,

    /// Context ID register (`CONTEXTIDR_EL1`).
    ContextidrEl1,

    /// Memory attribute indirection register (`MAIR_EL1`).
    MairEl1,
}

/// Event generated when a monitored system register is written.
#[derive(Debug, Clone, Copy)]
pub struct EventWriteSystemRegister {
    /// System register being written.
    pub register: SystemRegister,

    /// Value the guest is writing.
    pub new_value: u64,

    /// Value of the register before the write.
    pub old_value: u64,
}

/// Event generated after a single instruction step completes.
///
/// The address of the stepped instruction is read from the vCPU registers.
#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep;

/// Reason of a VMI event.
#[derive(Debug, Clone, Copy)]
pub enum EventReason<Geometry> {
    /// Memory access event.
    MemoryAccess(EventMemoryAccess<Geometry>),

    /// System register write event.
    WriteSystemRegister(EventWriteSystemRegister),

    /// Interrupt or exception event.
    Interrupt(EventInterrupt<Geometry>),

    /// Single-step event.
    Singlestep(EventSinglestep),
}

impl<Geometry> EventReason<Geometry> {
    /// Returns the system register write event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a system register write event.
    pub fn as_write_system_register(&self) -> &EventWriteSystemRegister {
        match self {
            Self::WriteSystemRegister(write_system_register) => write_system_register,
            _ => panic!("EventReason is not a WriteSystemRegister"),
        }
    }
}

/// Hardware events that can be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor writes to a specific system register.
    Register(SystemRegister),

    /// Monitor single-step execution of instructions.
    Singlestep,

    /// Monitor guest software breakpoints (`BRK`).
    Breakpoint,
}
