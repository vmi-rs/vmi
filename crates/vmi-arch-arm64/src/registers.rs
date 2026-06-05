/// The state of the CPU registers.
///
/// Mirrors the AArch64 register snapshot exposed by the KVM driver: the
/// general-purpose registers `x0`-`x30`, the program counter, the processor
/// state, and the EL1 system registers that drive stage-1 translation.
#[expect(missing_docs)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    pub regs: [u64; 31],
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub pc: u64,
    pub pstate: u64,

    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub sctlr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub contextidr_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub tpidr_el0: u64,
    pub tpidr_el1: u64,
    pub tpidrro_el0: u64,
}

/// General-purpose registers.
///
/// Holds the AArch64 integer register file `x0`-`x30`, the `EL0` stack
/// pointer, and the program counter.
#[expect(missing_docs)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GpRegisters {
    pub regs: [u64; 31],
    pub sp_el0: u64,
    pub pc: u64,
}

#[cfg(test)]
mod tests {
    use vmi_core::{Pa, Va, arch::Registers as _};

    use super::Registers;

    /// Confirms a low virtual address (bit 55 clear) selects `TTBR0_EL1`.
    #[test]
    fn low_va_uses_ttbr0() {
        let mut r = Registers::default();
        r.ttbr0_el1 = 0x1_0000;
        r.ttbr1_el1 = 0x2_0000;
        assert_eq!(r.translation_root(Va(0x0000_0000_0040_0000)), Pa(0x1_0000));
    }

    /// Confirms a high virtual address (bit 55 set) selects `TTBR1_EL1`.
    #[test]
    fn high_va_uses_ttbr1() {
        let mut r = Registers::default();
        r.ttbr0_el1 = 0x1_0000;
        r.ttbr1_el1 = 0x2_0000;
        assert_eq!(r.translation_root(Va(0xffff_8000_0000_0000)), Pa(0x2_0000));
    }
}
