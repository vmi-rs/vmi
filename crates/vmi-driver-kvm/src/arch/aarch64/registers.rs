use vmi_arch_aarch64::{Pstate, Registers};

use crate::FromExt;

impl FromExt<&kvm::sys::kvm_vmi_regs> for Registers {
    fn from_ext(raw: &kvm::sys::kvm_vmi_regs) -> Self {
        Self {
            x: raw.regs,
            sp: raw.sp,
            pc: raw.pc,
            pstate: Pstate(raw.pstate),

            sctlr_el1: raw.sctlr_el1,
            ttbr0_el1: raw.ttbr0_el1,
            ttbr1_el1: raw.ttbr1_el1,
            tcr_el1: raw.tcr_el1,
            esr_el1: raw.esr_el1,
            far_el1: raw.far_el1,
            mair_el1: raw.mair_el1,
            contextidr_el1: raw.contextidr_el1,

            vbar_el1: raw.vbar_el1,
            tpidr_el1: raw.tpidr_el1,
            sp_el0: raw.sp_el0,
        }
    }
}

impl FromExt<&Registers> for kvm::sys::kvm_vmi_regs {
    fn from_ext(regs: &Registers) -> Self {
        Self {
            regs: regs.x,
            sp: regs.sp,
            pc: regs.pc,
            pstate: regs.pstate.into(),

            // System registers are read-only in ring response,
            // but we write them back for completeness.
            sctlr_el1: regs.sctlr_el1,
            ttbr0_el1: regs.ttbr0_el1,
            ttbr1_el1: regs.ttbr1_el1,
            tcr_el1: regs.tcr_el1,
            esr_el1: regs.esr_el1,
            far_el1: regs.far_el1,
            mair_el1: regs.mair_el1,
            contextidr_el1: regs.contextidr_el1,
            vbar_el1: regs.vbar_el1,
            tpidr_el1: regs.tpidr_el1,
            sp_el0: regs.sp_el0,
        }
    }
}
