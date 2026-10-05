/// Exception class (`ESR_ELx.EC`) of an instruction abort from a lower
/// exception level.
const EC_IABT_LOW: u64 = 0x20;

/// Exception class (`ESR_ELx.EC`) of an instruction abort taken without a
/// change in exception level.
const EC_IABT_CUR: u64 = 0x21;

/// Exception class (`ESR_ELx.EC`) of a data abort from a lower exception
/// level.
const EC_DABT_LOW: u64 = 0x24;

/// Exception class (`ESR_ELx.EC`) of a data abort taken without a change in
/// exception level.
const EC_DABT_CUR: u64 = 0x25;

/// Exception class (`ESR_ELx.EC`) of a `BRK` instruction in AArch64 state.
const EC_BRK64: u64 = 0x3c;

/// Instruction length bit (`ESR_ELx.IL`), set for 32-bit instructions.
const ESR_IL: u64 = 1 << 25;

/// Write-not-Read bit (`ESR_ELx.ISS.WnR`) of a data abort.
const ESR_WNR: u64 = 1 << 6;

/// Fault status code field (`ESR_ELx.ISS.xFSC`) of an abort.
const ESR_FSC_MASK: u64 = 0x3f;

/// Fault status code of a level 3 translation fault.
///
/// An access to a valid but non-resident final-level page raises this fault,
/// which drives the guest's demand-paging handler.
const FSC_TRANSLATION_L3: u64 = 0x07;

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

    /// Creates the synchronous exception raised by a `BRK #imm` instruction.
    pub fn software_breakpoint(imm: u16) -> Self {
        Self::breakpoint((EC_BRK64 << 26) | ESR_IL | u64::from(imm))
    }

    /// Creates a synchronous data abort that reports a level 3 translation
    /// fault on a read of `far`.
    ///
    /// Delivering it drives the guest's demand-paging handler for `far`, which
    /// makes a valid but non-resident page resident. The exception level
    /// encoded in the syndrome is not significant. The hypervisor derives it
    /// from the vCPU state at injection.
    pub fn page_fault(far: u64) -> Self {
        Self {
            typ: InterruptType::Synchronous,
            esr: (EC_DABT_LOW << 26) | ESR_IL | FSC_TRANSLATION_L3,
            far,
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

    /// Checks whether the entry is an instruction abort.
    pub fn is_instruction_abort(&self) -> bool {
        self.typ == InterruptType::Synchronous
            && matches!(self.exception_class(), EC_IABT_LOW | EC_IABT_CUR)
    }

    /// Checks whether the entry is a data abort.
    pub fn is_data_abort(&self) -> bool {
        self.typ == InterruptType::Synchronous
            && matches!(self.exception_class(), EC_DABT_LOW | EC_DABT_CUR)
    }

    /// Returns the fault status code (`ESR_ELx.ISS.xFSC`) of an abort.
    pub fn fault_status_code(&self) -> u8 {
        (self.esr & ESR_FSC_MASK) as u8
    }

    /// Checks whether a data abort was caused by a write (`ESR_ELx.ISS.WnR`).
    pub fn is_write_fault(&self) -> bool {
        self.esr & ESR_WNR != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{Interrupt, InterruptType};

    #[test]
    fn software_breakpoint_carries_the_comment() {
        let interrupt = Interrupt::software_breakpoint(0xf000);
        assert!(interrupt.is_software_breakpoint());
        assert_eq!(interrupt.esr & 0xffff, 0xf000);
        assert!(!interrupt.is_instruction_abort());
    }

    #[test]
    fn page_fault_is_a_data_read_translation_fault() {
        let interrupt = Interrupt::page_fault(0x1_0000_4000);
        assert_eq!(interrupt.far, 0x1_0000_4000);
        assert_eq!(interrupt.fault_status_code(), 0x07);
        assert!(interrupt.is_data_abort());
        assert!(!interrupt.is_instruction_abort());
        assert!(!interrupt.is_write_fault());
        assert!(!interrupt.is_software_breakpoint());
    }

    #[test]
    fn instruction_abort_is_recognized_at_both_levels() {
        for ec in [0x20, 0x21] {
            let interrupt = Interrupt {
                typ: InterruptType::Synchronous,
                esr: (ec << 26) | 0x0f,
                far: 0,
            };
            assert!(interrupt.is_instruction_abort());
            assert_eq!(interrupt.fault_status_code(), 0x0f);
        }
    }
}
