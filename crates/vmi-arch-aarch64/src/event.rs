use vmi_core::{Gfn, MemoryAccess, Pa, Va};

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

/// BRK software breakpoint event.
#[derive(Debug, Clone, Copy)]
pub struct EventBreakpoint {
    /// GFN of the breakpoint instruction (gpa >> PAGE_SHIFT).
    pub gfn: Gfn,
    /// Program counter at the breakpoint.
    pub pc: Va,
    /// Immediate value from BRK #imm16.
    pub comment: u16,
}

/// System register write event.
#[derive(Debug, Clone, Copy)]
pub struct EventSysreg {
    /// Which system register was written.
    pub register: SystemRegister,
    /// Value before the write.
    pub old_value: u64,
    /// Value the guest is writing.
    pub new_value: u64,
}

/// Single-step completion event.
#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep {
    /// GFN of the instruction.
    pub gfn: Gfn,
}

/// Reason for an event.
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    /// Memory access event (read/write/execute).
    MemoryAccess(EventMemoryAccess),
    /// BRK software breakpoint event.
    Breakpoint(EventBreakpoint),
    /// System register write event.
    Sysreg(EventSysreg),
    /// Single-step completion event.
    Singlestep(EventSinglestep),
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

    /// Returns the breakpoint event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a breakpoint event.
    pub fn as_breakpoint(&self) -> &EventBreakpoint {
        match self {
            Self::Breakpoint(breakpoint) => breakpoint,
            _ => panic!("EventReason is not a Breakpoint"),
        }
    }

    /// Returns the sysreg event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a sysreg event.
    pub fn as_sysreg(&self) -> &EventSysreg {
        match self {
            Self::Sysreg(sysreg) => sysreg,
            _ => panic!("EventReason is not a Sysreg"),
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
}

/// Specifies which hardware events should be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor BRK software breakpoints.
    Breakpoint,
    /// Monitor system register writes.
    Sysreg(SystemRegister),
    /// Monitor single-step completion.
    Singlestep,
}

/// System registers that can be monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    /// System Control Register EL1.
    SctlrEl1,
    /// Translation Table Base Register 0 EL1.
    Ttbr0El1,
    /// Translation Table Base Register 1 EL1.
    Ttbr1El1,
    /// Translation Control Register EL1.
    TcrEl1,
}
