//! Conversions between KVM register structs and the arm64 `Registers` type.

use kvm::{KvmVmiEvent, KvmVmiRegs, arch::arm64::KvmVmiRegsArm64};
use vmi_arch_arm64::Registers;

use crate::convert::FromExt;

impl FromExt<kvm::arch::arm64::Registers> for Registers {
    /// Converts a `KVM_GET_ONE_REG` register snapshot to `vmi_arch_arm64::Registers`.
    fn from_ext(value: kvm::arch::arm64::Registers) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

impl FromExt<&Registers> for kvm::arch::arm64::Registers {
    /// Converts `vmi_arch_arm64::Registers` back to a `KVM_SET_ONE_REG` snapshot.
    fn from_ext(value: &Registers) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

impl FromExt<&KvmVmiRegsArm64> for Registers {
    /// Converts an in-event register snapshot to `vmi_arch_arm64::Registers`.
    fn from_ext(value: &KvmVmiRegsArm64) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

impl FromExt<&Registers> for KvmVmiRegsArm64 {
    /// Converts `vmi_arch_arm64::Registers` to an in-event register snapshot.
    fn from_ext(value: &Registers) -> Self {
        Self {
            regs: value.regs,
            sp_el0: value.sp_el0,
            sp_el1: value.sp_el1,
            pc: value.pc,
            pstate: value.pstate,
            ttbr0_el1: value.ttbr0_el1,
            ttbr1_el1: value.ttbr1_el1,
            tcr_el1: value.tcr_el1,
            sctlr_el1: value.sctlr_el1,
            mair_el1: value.mair_el1,
            vbar_el1: value.vbar_el1,
            contextidr_el1: value.contextidr_el1,
            elr_el1: value.elr_el1,
            spsr_el1: value.spsr_el1,
            esr_el1: value.esr_el1,
            far_el1: value.far_el1,
            tpidr_el0: value.tpidr_el0,
            tpidr_el1: value.tpidr_el1,
            tpidrro_el0: value.tpidrro_el0,
        }
    }
}

impl FromExt<&KvmVmiEvent> for Registers {
    /// Extracts arm64 registers from the in-event snapshot.
    fn from_ext(value: &KvmVmiEvent) -> Self {
        let KvmVmiRegs::Arm64(regs) = value.regs;
        Registers::from_ext(&regs)
    }
}

#[cfg(test)]
mod tests {
    use kvm::arch::arm64::Registers as KvmRegisters;

    use super::*;

    /// Confirms that every field is mapped correctly from a libkvm snapshot to
    /// `vmi_arch_arm64::Registers`.
    #[test]
    fn from_kvm_registers_maps_all_fields() {
        let mut src = KvmRegisters::default();
        src.regs[0] = 0xaa;
        src.regs[30] = 0xbb;
        src.sp_el0 = 0x2000;
        src.sp_el1 = 0x3000;
        src.pc = 0x1000;
        src.pstate = 0xcc;
        src.ttbr0_el1 = 0x4000;
        src.ttbr1_el1 = 0x5000;
        src.tcr_el1 = 0x11;
        src.sctlr_el1 = 0x22;
        src.mair_el1 = 0x33;
        src.vbar_el1 = 0x6000;
        src.contextidr_el1 = 0x44;
        src.elr_el1 = 0x7000;
        src.spsr_el1 = 0x55;
        src.esr_el1 = 0x66;
        src.far_el1 = 0x8000;
        src.tpidr_el0 = 0x77;
        src.tpidr_el1 = 0x88;
        src.tpidrro_el0 = 0x99;

        let dst = Registers::from_ext(src);

        assert_eq!(dst.regs[0], 0xaa);
        assert_eq!(dst.regs[30], 0xbb);
        assert_eq!(dst.sp_el0, 0x2000);
        assert_eq!(dst.sp_el1, 0x3000);
        assert_eq!(dst.pc, 0x1000);
        assert_eq!(dst.pstate, 0xcc);
        assert_eq!(dst.ttbr0_el1, 0x4000);
        assert_eq!(dst.ttbr1_el1, 0x5000);
        assert_eq!(dst.tcr_el1, 0x11);
        assert_eq!(dst.sctlr_el1, 0x22);
        assert_eq!(dst.mair_el1, 0x33);
        assert_eq!(dst.vbar_el1, 0x6000);
        assert_eq!(dst.contextidr_el1, 0x44);
        assert_eq!(dst.elr_el1, 0x7000);
        assert_eq!(dst.spsr_el1, 0x55);
        assert_eq!(dst.esr_el1, 0x66);
        assert_eq!(dst.far_el1, 0x8000);
        assert_eq!(dst.tpidr_el0, 0x77);
        assert_eq!(dst.tpidr_el1, 0x88);
        assert_eq!(dst.tpidrro_el0, 0x99);
    }

    /// Confirms that the round-trip through `KvmRegisters` is lossless.
    #[test]
    fn round_trip_through_kvm_registers() {
        let mut original = KvmRegisters::default();
        original.regs[0] = 0xdead;
        original.pc = 0x1000;
        original.sp_el0 = 0x2000;
        original.ttbr0_el1 = 0x3000;
        original.ttbr1_el1 = 0x4000;
        original.vbar_el1 = 0x5000;

        let vmi = Registers::from_ext(original);
        let back = KvmRegisters::from_ext(&vmi);

        assert_eq!(back, original);
    }
}
