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

    /// Interrupt or exception event.
    Interrupt(EventInterrupt<Geometry>),

    /// Single-step event.
    Singlestep(EventSinglestep),
}

/// Hardware events that can be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor single-step execution of instructions.
    Singlestep,

    /// Monitor guest software breakpoints (`BRK`).
    Breakpoint,
}
