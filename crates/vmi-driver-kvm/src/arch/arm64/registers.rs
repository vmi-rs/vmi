//! Conversions between KVM register structs and the arm64 `Registers` type.

use kvm::{KvmVmiEvent, KvmVmiRegs, arch::arm64::KvmVmiRegsArm64};
use vmi_arch_arm64::{PagingGeometry, Registers};

use crate::convert::FromExt;

impl<Geometry> FromExt<kvm::arch::arm64::Registers> for Registers<Geometry>
where
    Geometry: PagingGeometry,
{
    /// Converts a `KVM_GET_ONE_REG` register snapshot to `vmi_arch_arm64::Registers`.
    fn from_ext(value: kvm::arch::arm64::Registers) -> Self {
        let mut registers = Self::default();
        registers.regs = value.regs;
        registers.sp_el0 = value.sp_el0;
        registers.sp_el1 = value.sp_el1;
        registers.pc = value.pc;
        registers.pstate = value.pstate;
        registers.ttbr0_el1 = value.ttbr0_el1;
        registers.ttbr1_el1 = value.ttbr1_el1;
        registers.tcr_el1 = value.tcr_el1;
        registers.sctlr_el1 = value.sctlr_el1;
        registers.mair_el1 = value.mair_el1;
        registers.vbar_el1 = value.vbar_el1;
        registers.contextidr_el1 = value.contextidr_el1;
        registers.elr_el1 = value.elr_el1;
        registers.spsr_el1 = value.spsr_el1;
        registers.esr_el1 = value.esr_el1;
        registers.far_el1 = value.far_el1;
        registers.tpidr_el0 = value.tpidr_el0;
        registers.tpidr_el1 = value.tpidr_el1;
        registers.tpidrro_el0 = value.tpidrro_el0;
        registers
    }
}

impl<Geometry> FromExt<&Registers<Geometry>> for kvm::arch::arm64::Registers
where
    Geometry: PagingGeometry,
{
    /// Converts `vmi_arch_arm64::Registers` back to a `KVM_SET_ONE_REG` snapshot.
    fn from_ext(value: &Registers<Geometry>) -> Self {
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

impl<Geometry> FromExt<&KvmVmiRegsArm64> for Registers<Geometry>
where
    Geometry: PagingGeometry,
{
    /// Converts an in-event register snapshot to `vmi_arch_arm64::Registers`.
    fn from_ext(value: &KvmVmiRegsArm64) -> Self {
        let mut registers = Self::default();
        registers.regs = value.regs;
        registers.sp_el0 = value.sp_el0;
        registers.sp_el1 = value.sp_el1;
        registers.pc = value.pc;
        registers.pstate = value.pstate;
        registers.ttbr0_el1 = value.ttbr0_el1;
        registers.ttbr1_el1 = value.ttbr1_el1;
        registers.tcr_el1 = value.tcr_el1;
        registers.sctlr_el1 = value.sctlr_el1;
        registers.mair_el1 = value.mair_el1;
        registers.vbar_el1 = value.vbar_el1;
        registers.contextidr_el1 = value.contextidr_el1;
        registers.elr_el1 = value.elr_el1;
        registers.spsr_el1 = value.spsr_el1;
        registers.esr_el1 = value.esr_el1;
        registers.far_el1 = value.far_el1;
        registers.tpidr_el0 = value.tpidr_el0;
        registers.tpidr_el1 = value.tpidr_el1;
        registers.tpidrro_el0 = value.tpidrro_el0;
        registers
    }
}

impl<Geometry> FromExt<&Registers<Geometry>> for KvmVmiRegsArm64
where
    Geometry: PagingGeometry,
{
    /// Converts `vmi_arch_arm64::Registers` to an in-event register snapshot.
    fn from_ext(value: &Registers<Geometry>) -> Self {
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

impl<Geometry> FromExt<&KvmVmiEvent> for Registers<Geometry>
where
    Geometry: PagingGeometry,
{
    /// Extracts arm64 registers from the in-event snapshot.
    fn from_ext(value: &KvmVmiEvent) -> Self {
        let KvmVmiRegs::Arm64(regs) = value.regs;
        Self::from_ext(&regs)
    }
}
