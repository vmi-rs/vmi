/// Exception class (`ESR_ELx.EC`) of a `BRK` instruction in AArch64 state.
const EC_BRK64: u64 = 0x3c;

/// Type of AArch64 exception entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// Synchronous exception, such as a `BRK` software breakpoint.
    Synchronous,

    /// Asynchronous IRQ.
    Irq,

    /// Asynchronous FIQ.
    Fiq,

    /// System error (SError) interrupt.
    SError,
}

/// Information about an AArch64 exception or interrupt.
#[derive(Debug, Clone, Copy)]
pub struct Interrupt {
    /// Kind of exception entry.
    pub typ: InterruptType,

    /// Exception syndrome (`ESR_EL1`) of the entry.
    pub esr: u64,

    /// Faulting virtual address (`FAR_EL1`), when applicable.
    pub far: u64,
}

impl Interrupt {
    /// Creates a synchronous software breakpoint exception (`BRK`).
    pub fn breakpoint(esr: u64) -> Self {
        Self {
            typ: InterruptType::Synchronous,
            esr,
            far: 0,
        }
    }

    /// Returns the exception class (`ESR_ELx.EC`) of the entry.
    pub fn exception_class(&self) -> u64 {
        (self.esr >> 26) & 0x3f
    }

    /// Checks whether the entry is a `BRK` instruction executed in AArch64
    /// state.
    pub fn is_software_breakpoint(&self) -> bool {
        self.typ == InterruptType::Synchronous && self.exception_class() == EC_BRK64
    }
}
