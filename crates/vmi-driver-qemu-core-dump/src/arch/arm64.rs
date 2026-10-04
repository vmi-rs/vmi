use elf::abi::EM_AARCH64;
use vmi_arch_arm64::{Arm64, PagingGeometry, Registers};
use vmi_core::arch::Registers as _;

use crate::{ArchAdapter, Error, JsonRegisters};

/// Size of the AArch64 `struct elf_prstatus`.
const PRSTATUS_SIZE: usize = 392;

/// Offset of `pr_reg` within the AArch64 `struct elf_prstatus`.
///
/// `pr_reg` holds `x0` to `x30`, `sp`, `pc` and `pstate` as 64-bit values.
const PRSTATUS_REG_OFFSET: usize = 112;

/// Index of `sp` within `pr_reg`.
const REG_SP: usize = 31;

/// Index of `pc` within `pr_reg`.
const REG_PC: usize = 32;

/// Index of `pstate` within `pr_reg`.
const REG_PSTATE: usize = 33;

impl<Geometry> ArchAdapter for Arm64<Geometry>
where
    Geometry: PagingGeometry,
{
    const ELF_MACHINE: u16 = EM_AARCH64;

    fn registers(prstatus: &[u8], json: &JsonRegisters) -> Result<Self::Registers, Error> {
        let vcpu = json.vcpu();

        if prstatus.len() != PRSTATUS_SIZE {
            return Err(Error::InvalidPrstatus {
                vcpu,
                size: prstatus.len(),
                expected: PRSTATUS_SIZE,
            });
        }

        let reg = |index: usize| {
            let offset = PRSTATUS_REG_OFFSET + index * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&prstatus[offset..offset + 8]);
            u64::from_le_bytes(bytes)
        };

        let check = |register: &'static str, note: u64| {
            let value = json.get(register)?;
            if value != note {
                return Err(Error::RegisterMismatch {
                    vcpu,
                    register,
                    note,
                    json: value,
                });
            }

            Ok(())
        };

        check("pc", reg(REG_PC))?;
        check("sp", reg(REG_SP))?;
        check("x30", reg(30))?;

        let tcr_el1 = json.get("TCR_EL1")?;
        if !Geometry::matches_tcr(tcr_el1) {
            return Err(Error::TranslationControlMismatch { vcpu, tcr: tcr_el1 });
        }

        // The kernel translation root (TTBR1_EL1) could be inferred from
        // memory alone, through the XNU `cpu_ttep` variable located via
        // `gVirtBase`/`gPhysBase` and the kernel collection header. This
        // driver intentionally takes it from the register file instead.
        let mut registers = Registers::<Geometry>::default();
        for (index, value) in registers.regs.iter_mut().enumerate() {
            *value = reg(index);
        }
        registers.pc = reg(REG_PC);
        registers.pstate = reg(REG_PSTATE);
        registers.sp_el0 = json.get("SP_EL0")?;
        registers.sp_el1 = json.get("SP_EL1")?;
        registers.ttbr0_el1 = json.get("TTBR0_EL1")?;
        registers.ttbr1_el1 = json.get("TTBR1_EL1")?;
        registers.tcr_el1 = tcr_el1;
        registers.sctlr_el1 = json.get("SCTLR_EL1")?;
        registers.mair_el1 = json.get("MAIR_EL1")?;
        registers.vbar_el1 = json.get("VBAR_EL1")?;
        registers.contextidr_el1 = json.get("CONTEXTIDR_EL1")?;
        registers.elr_el1 = json.get("ELR_EL1")?;
        registers.spsr_el1 = json.get("SPSR_EL1")?;
        registers.esr_el1 = json.get("ESR_EL1")?;
        registers.far_el1 = json.get("FAR_EL1")?;
        registers.tpidr_el0 = json.get("TPIDR_EL0")?;
        registers.tpidr_el1 = json.get("TPIDR_EL1")?;
        registers.tpidrro_el0 = json.get("TPIDRRO_EL0")?;

        // The banked stack pointer of the current mode may lag behind the
        // live value, so the `sp` of the note wins for the active bank.
        registers.set_stack_pointer(reg(REG_SP));

        Ok(registers)
    }
}
