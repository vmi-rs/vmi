/// Processor state (SPSR_EL2).
///
/// Newtype wrapper around `u64` representing the saved program status register.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pstate(pub u64);

impl Pstate {
    /// Negative condition flag (bit 31).
    pub fn n(self) -> bool { self.0 & (1 << 31) != 0 }
    /// Zero condition flag (bit 30).
    pub fn z(self) -> bool { self.0 & (1 << 30) != 0 }
    /// Carry condition flag (bit 29).
    pub fn c(self) -> bool { self.0 & (1 << 29) != 0 }
    /// Overflow condition flag (bit 28).
    pub fn v(self) -> bool { self.0 & (1 << 28) != 0 }
    /// Software step bit (bit 21).
    pub fn ss(self) -> bool { self.0 & (1 << 21) != 0 }
    /// Illegal execution state bit (bit 20).
    pub fn il(self) -> bool { self.0 & (1 << 20) != 0 }
    /// Debug mask bit (bit 9).
    pub fn d(self) -> bool { self.0 & (1 << 9) != 0 }
    /// SError mask bit (bit 8).
    pub fn a(self) -> bool { self.0 & (1 << 8) != 0 }
    /// IRQ mask bit (bit 7).
    pub fn i(self) -> bool { self.0 & (1 << 7) != 0 }
    /// FIQ mask bit (bit 6).
    pub fn f(self) -> bool { self.0 & (1 << 6) != 0 }
    /// Not Register Width. 0 = AArch64 (bit 4).
    pub fn nrw(self) -> bool { self.0 & (1 << 4) != 0 }
    /// Exception level (bits 3:2).
    pub fn el(self) -> u8 { ((self.0 >> 2) & 0x3) as u8 }
    /// Stack pointer select. 0 = SP_EL0, 1 = SP_ELx (bit 0).
    pub fn sp(self) -> bool { self.0 & 1 != 0 }
}

impl From<u64> for Pstate {
    fn from(value: u64) -> Self { Self(value) }
}

impl From<Pstate> for u64 {
    fn from(value: Pstate) -> Self { value.0 }
}

/// Full CPU register state snapshot.
#[expect(missing_docs)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Registers {
    // General-purpose registers
    pub x: [u64; 31],       // x0-x30
    pub sp: u64,             // SP_EL1
    pub pc: u64,             // ELR_EL2 (program counter)
    pub pstate: Pstate,      // SPSR_EL2

    // System registers (from ring event)
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub mair_el1: u64,
    pub contextidr_el1: u64,

    // Extra registers (populated from KVM_GET_ONE_REG when available)
    pub vbar_el1: u64,
    pub tpidr_el1: u64,
    pub sp_el0: u64,
}

/// General-purpose registers subset for event response SET_REGS.
#[expect(missing_docs)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GpRegisters {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: Pstate,
}
