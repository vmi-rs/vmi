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
}
