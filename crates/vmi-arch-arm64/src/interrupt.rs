/// Type of AArch64 exception entry.
///
/// Mirrors the synchronous/IRQ/FIQ/SError taxonomy of the AArch64 exception
/// model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// Synchronous exception (for example a `BRK` software breakpoint).
    Synchronous,

    /// Asynchronous IRQ.
    Irq,

    /// Asynchronous FIQ.
    Fiq,

    /// System error (SError) interrupt.
    SError,
}

/// `ESR_ELx.FSC` for a level-3 translation fault - the status code a real
/// access to a valid but non-resident final-level (4 KiB) page produces, and
/// thus the code that drives the guest's demand-paging handler.
const ESR_FSC_TRANSLATION_L3: u8 = 0x07;

/// Information about an AArch64 exception or interrupt.
#[derive(Debug, Clone, Copy)]
pub struct Interrupt {
    /// Kind of exception entry.
    pub typ: InterruptType,

    /// Exception syndrome (`ESR_EL1`) for the entry.
    pub esr: u64,

    /// Faulting virtual address (`FAR_EL1`), when applicable.
    pub far: u64,

    /// Fault status code (`ESR_ELx.FSC`) for an injected abort. Ignored unless
    /// the entry is delivered as a Data or Instruction Abort.
    pub fsc: u8,

    /// Write-not-Read flag for an injected data abort.
    pub write: bool,
}

impl Interrupt {
    /// Creates a synchronous software breakpoint exception (`BRK`).
    pub fn breakpoint(esr: u64) -> Self {
        Self {
            typ: InterruptType::Synchronous,
            esr,
            far: 0,
            fsc: 0,
            write: false,
        }
    }

    /// Creates a synchronous data abort carrying a level-3 translation fault at
    /// `far`. This is the AArch64 analog of x86 page-fault injection: delivering
    /// it drives the guest's demand-paging handler for `far`, faulting in a
    /// valid but non-resident page so its contents become readable.
    pub fn page_fault(far: u64) -> Self {
        Self {
            typ: InterruptType::Synchronous,
            esr: 0,
            far,
            fsc: ESR_FSC_TRANSLATION_L3,
            write: false,
        }
    }
}
