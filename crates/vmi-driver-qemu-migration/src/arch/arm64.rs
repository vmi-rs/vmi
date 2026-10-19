use vmi_arch_arm64::{Arm64, PagingGeometry, Registers};
use vmi_core::arch::Registers as _;

use super::{ArchAdapter, block_length};
use crate::{CpuState, Error, RamRange};

/// Name of the main RAM block of the `virt` machine (`default_ram_id` in
/// `hw/arm/virt.c`).
const VIRT_RAM: &str = "mach-virt.ram";

/// Guest physical address of the RAM of the `virt` machine (`VIRT_MEM` in
/// `hw/arm/virt.c`).
const VIRT_RAM_BASE: u64 = 0x4000_0000;

/// Name of the main RAM block of the `vmapple` machine (`default_ram_id` in
/// `hw/vmapple/vmapple.c`).
const VMAPPLE_RAM: &str = "mach-vmapple.ram";

/// Guest physical address of the RAM of the `vmapple` machine
/// (`VMAPPLE_MEM` in `hw/vmapple/vmapple.c`).
const VMAPPLE_RAM_BASE: u64 = 0x7000_0000;

/// Bit of `SCTLR_EL1` that enables stage-1 translation at EL1 and EL0.
const SCTLR_EL1_M: u64 = 1 << 0;

/// Returns the register index under which QEMU lists an AArch64 system
/// register in its `cpreg` list.
///
/// QEMU numbers system registers as KVM does, for TCG as well
/// (`cpreg_to_kvm_id` in `target/arm/cpregs.h`). The index combines the
/// 64-bit register size with the `op0`, `op1`, `CRn`, `CRm` and `op2`
/// fields of the register encoding (`CP_REG_ARM64_SYSREG_*` in
/// `target/arm/kvm-consts.h`).
const fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    0x6030_0000_0013_0000 | (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

/// `SCTLR_EL1`, encoded as `S3_0_C1_C0_0`.
const SCTLR_EL1: u64 = sysreg(3, 0, 1, 0, 0);

/// `TTBR0_EL1`, encoded as `S3_0_C2_C0_0`.
const TTBR0_EL1: u64 = sysreg(3, 0, 2, 0, 0);

/// `TTBR1_EL1`, encoded as `S3_0_C2_C0_1`.
const TTBR1_EL1: u64 = sysreg(3, 0, 2, 0, 1);

/// `TCR_EL1`, encoded as `S3_0_C2_C0_2`.
const TCR_EL1: u64 = sysreg(3, 0, 2, 0, 2);

/// `ESR_EL1`, encoded as `S3_0_C5_C2_0`.
const ESR_EL1: u64 = sysreg(3, 0, 5, 2, 0);

/// `FAR_EL1`, encoded as `S3_0_C6_C0_0`.
const FAR_EL1: u64 = sysreg(3, 0, 6, 0, 0);

/// `MAIR_EL1`, encoded as `S3_0_C10_C2_0`.
const MAIR_EL1: u64 = sysreg(3, 0, 10, 2, 0);

/// `VBAR_EL1`, encoded as `S3_0_C12_C0_0`.
const VBAR_EL1: u64 = sysreg(3, 0, 12, 0, 0);

/// `CONTEXTIDR_EL1`, encoded as `S3_0_C13_C0_1`.
const CONTEXTIDR_EL1: u64 = sysreg(3, 0, 13, 0, 1);

/// `TPIDR_EL1`, encoded as `S3_0_C13_C0_4`.
const TPIDR_EL1: u64 = sysreg(3, 0, 13, 0, 4);

/// `TPIDR_EL0`, encoded as `S3_3_C13_C0_2`.
const TPIDR_EL0: u64 = sysreg(3, 3, 13, 0, 2);

/// `TPIDRRO_EL0`, encoded as `S3_3_C13_C0_3`.
const TPIDRRO_EL0: u64 = sysreg(3, 3, 13, 0, 3);

impl<Geometry> ArchAdapter for Arm64<Geometry>
where
    Geometry: PagingGeometry,
{
    /// Returns the RAM of the `virt` and `vmapple` machines.
    ///
    /// Both machines map their main RAM block in one piece, at a base
    /// address that does not depend on the RAM size.
    fn ram_ranges(machine: &str, blocks: &[(&str, u64)]) -> Result<Vec<RamRange>, Error> {
        let (block, address) = if machine == "virt" || machine.starts_with("virt-") {
            (VIRT_RAM, VIRT_RAM_BASE)
        }
        else if machine == "vmapple" {
            (VMAPPLE_RAM, VMAPPLE_RAM_BASE)
        }
        else {
            return Err(Error::UnsupportedMachine {
                machine: machine.into(),
            });
        };

        Ok(vec![RamRange {
            block,
            offset: 0,
            address,
            length: block_length(blocks, block)?,
        }])
    }

    /// Builds the registers from a `cpu` section of `vmstate_arm_cpu`
    /// (`target/arm/machine.c`).
    ///
    /// Fails when the MMU is on and `TCR_EL1` does not match the paging
    /// geometry.
    fn registers(cpu: &CpuState) -> Result<Self::Registers, Error> {
        let vcpu = cpu.vcpu();
        let system = SystemRegisters::new(cpu)?;

        let mut registers = Registers::<Geometry>::default();
        for (index, value) in registers.regs.iter_mut().enumerate() {
            *value = cpu.uint("env.xregs", index)?;
        }

        registers.pc = cpu.uint("env.pc", 0)?;

        // `put_cpsr` writes the lower 32 bits of PSTATE in SPSR layout. The
        // `cpu/pstate64` subsection holds all 64 bits when the upper half is
        // not zero.
        registers.pstate = match cpu.subsection("cpu/pstate64") {
            Some(pstate64) => pstate64.uint("pstate64", 0)?,
            None => cpu.uint("cpsr", 0)?,
        };

        // `env.sp_el` holds SP_EL0 to SP_EL3. `env.elr_el` holds ELR_EL1 at
        // index 1, and `env.banked_spsr` holds SPSR_EL1 at index 1, the bank
        // of EL1 (`aarch64_banked_spsr_index` in `target/arm/internals.h`).
        registers.sp_el0 = cpu.uint("env.sp_el", 0)?;
        registers.sp_el1 = cpu.uint("env.sp_el", 1)?;
        registers.elr_el1 = cpu.uint("env.elr_el", 1)?;
        registers.spsr_el1 = cpu.uint("env.banked_spsr", 1)?;

        registers.ttbr0_el1 = system.get(TTBR0_EL1, "TTBR0_EL1")?;
        registers.ttbr1_el1 = system.get(TTBR1_EL1, "TTBR1_EL1")?;
        registers.tcr_el1 = system.get(TCR_EL1, "TCR_EL1")?;
        registers.sctlr_el1 = system.get(SCTLR_EL1, "SCTLR_EL1")?;
        registers.mair_el1 = system.get(MAIR_EL1, "MAIR_EL1")?;
        registers.vbar_el1 = system.get(VBAR_EL1, "VBAR_EL1")?;
        registers.contextidr_el1 = system.get(CONTEXTIDR_EL1, "CONTEXTIDR_EL1")?;
        registers.esr_el1 = system.get(ESR_EL1, "ESR_EL1")?;
        registers.far_el1 = system.get(FAR_EL1, "FAR_EL1")?;
        registers.tpidr_el0 = system.get(TPIDR_EL0, "TPIDR_EL0")?;
        registers.tpidr_el1 = system.get(TPIDR_EL1, "TPIDR_EL1")?;
        registers.tpidrro_el0 = system.get(TPIDRRO_EL0, "TPIDRRO_EL0")?;

        // TCR_EL1 does not take part in translation while the MMU is off,
        // as before the guest kernel sets it up.
        if registers.sctlr_el1 & SCTLR_EL1_M != 0 && !Geometry::matches_tcr(registers.tcr_el1) {
            return Err(Error::TranslationControlMismatch {
                vcpu,
                tcr: registers.tcr_el1,
            });
        }

        // `env.xregs[31]` holds the current stack pointer. With TCG, QEMU
        // copies it to its bank in `env.sp_el` only when the exception level
        // changes (`aarch64_save_sp` in `target/arm/internals.h`). The bank in
        // `env.sp_el` can therefore be stale.
        registers.set_stack_pointer(cpu.uint("env.xregs", 31)?);

        Ok(registers)
    }
}

/// The system registers of one vCPU.
///
/// QEMU saves them as two arrays of the same length,
/// `cpreg_vmstate_indexes` and `cpreg_vmstate_values`. Each index names a
/// register as [`sysreg`] encodes it.
struct SystemRegisters<'a> {
    /// The `cpu` section of the vCPU.
    cpu: &'a CpuState<'a>,

    /// Number of entries of both arrays.
    count: usize,
}

impl<'a> SystemRegisters<'a> {
    /// Creates the system registers of the vCPU of `cpu`.
    fn new(cpu: &'a CpuState<'a>) -> Result<Self, Error> {
        let count = match cpu.count("cpreg_vmstate_indexes") {
            Some(count) => count,
            None => {
                return Err(Error::MissingField {
                    vcpu: cpu.vcpu(),
                    field: "cpreg_vmstate_indexes".into(),
                });
            }
        };

        Ok(Self { cpu, count })
    }

    /// Returns the value of the register with the index `index`.
    ///
    /// `name` names the register in the error when the list lacks it.
    fn get(&self, index: u64, name: &'static str) -> Result<u64, Error> {
        for position in 0..self.count {
            if self.cpu.uint("cpreg_vmstate_indexes", position)? == index {
                return self.cpu.uint("cpreg_vmstate_values", position);
            }
        }

        Err(Error::MissingSystemRegister {
            vcpu: self.cpu.vcpu(),
            register: name,
        })
    }
}
