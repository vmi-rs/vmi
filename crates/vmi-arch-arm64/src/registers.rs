/// The state of the CPU registers.
///
/// Holds the general-purpose registers, the banked stack pointers, the
/// program counter, the processor state and the EL1 system registers that
/// drive stage-1 translation and exception handling.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registers<Geometry> {
    /// Registers `x0` to `x30`. `x30` is the link register.
    pub regs: [u64; 31],

    /// Stack pointer used at EL0, and at EL1 when `PSTATE.SP` is clear.
    pub sp_el0: u64,

    /// Stack pointer used at EL1 when `PSTATE.SP` is set.
    pub sp_el1: u64,

    /// Program counter.
    pub pc: u64,

    /// Processor state in `SPSR` layout. `Bits[3:2]` hold the exception level
    /// and bit 0 selects the stack pointer.
    pub pstate: u64,

    /// Translation table base of the low half of the address space, with
    /// the ASID in `bits[63:48]`.
    pub ttbr0_el1: u64,

    /// Translation table base of the high half of the address space.
    pub ttbr1_el1: u64,

    /// Translation control register.
    pub tcr_el1: u64,

    /// System control register.
    pub sctlr_el1: u64,

    /// Memory attribute indirection register.
    pub mair_el1: u64,

    /// Vector base address register.
    pub vbar_el1: u64,

    /// Context ID register.
    pub contextidr_el1: u64,

    /// Exception link register.
    pub elr_el1: u64,

    /// Saved program status register.
    pub spsr_el1: u64,

    /// Exception syndrome register.
    pub esr_el1: u64,

    /// Fault address register.
    pub far_el1: u64,

    /// EL0 read/write software thread ID register.
    pub tpidr_el0: u64,

    /// EL1 software thread ID register.
    pub tpidr_el1: u64,

    /// EL0 read-only software thread ID register.
    pub tpidrro_el0: u64,

    _geometry: std::marker::PhantomData<Geometry>,
}

impl<Geometry> Registers<Geometry> {
    /// Checks if the active stack pointer is `SP_EL1`.
    ///
    /// `SP_EL1` is active when the exception level in `PSTATE` `bits[3:2]` is
    /// EL1 or higher and `PSTATE.SP` (bit 0) is set.
    pub fn uses_sp_el1(&self) -> bool {
        (self.pstate >> 2) & 0b11 != 0 && self.pstate & 1 != 0
    }
}

/// General-purpose registers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GpRegisters<Geometry> {
    /// Registers `x0` to `x30`. `x30` is the link register.
    pub regs: [u64; 31],

    /// Active stack pointer, selected by `pstate`.
    pub sp: u64,

    /// Program counter.
    pub pc: u64,

    /// Processor state in `SPSR` layout.
    pub pstate: u64,

    _geometry: std::marker::PhantomData<Geometry>,
}
