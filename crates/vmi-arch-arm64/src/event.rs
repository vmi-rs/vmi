use vmi_core::{Gfn, MemoryAccess, Pa, Va};

use crate::Interrupt;

/// Event generated when monitored memory is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess {
    /// Physical address that was accessed.
    pub pa: Pa,

    /// Virtual address that was accessed.
    pub va: Va,

    /// Type of access that occurred (read/write/execute).
    pub access: MemoryAccess,
}

/// Event generated when an interrupt or exception occurs.
#[derive(Debug, Clone, Copy)]
pub struct EventInterrupt {
    /// Returns the GFN of the instruction that raised the interrupt.
    pub gfn: Gfn,

    /// Information about the interrupt or exception.
    pub interrupt: Interrupt,
}

/// Classifies why a KVM VMI event fired.
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    /// Memory access event (read/write/execute).
    MemoryAccess(EventMemoryAccess),

    /// Interrupt or exception event.
    Interrupt(EventInterrupt),
}

/// Specifies which hardware events should be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor singlestep execution of instructions.
    Singlestep,

    /// Monitor guest software breakpoints (`BRK`).
    Breakpoint,
}
