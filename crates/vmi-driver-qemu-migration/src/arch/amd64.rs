use vmi_arch_amd64::{
    Amd64, Cr0, Cr2, Cr3, Cr4, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Gdtr, Idtr, MsrEfer, Registers,
    Rflags, SegmentAccess, SegmentDescriptor, Selector,
};

use super::{ArchAdapter, block_length};
use crate::{CpuState, Error, RamRange};

/// Name of the main RAM block of the PC machines (`default_ram_id` in
/// `hw/i386/pc.c`).
const PC_RAM: &str = "pc.ram";

/// Guest physical address of the RAM above 4 GiB (`above_4g_mem_start` in
/// `hw/i386/x86.c`).
const ABOVE_4G_MEM_START: u64 = 0x1_0000_0000;

/// Index of `ES` in `env.segs` (`R_ES` in `target/i386/cpu.h`).
const R_ES: usize = 0;

/// Index of `CS` in `env.segs`.
const R_CS: usize = 1;

/// Index of `SS` in `env.segs`.
const R_SS: usize = 2;

/// Index of `DS` in `env.segs`.
const R_DS: usize = 3;

/// Index of `FS` in `env.segs`.
const R_FS: usize = 4;

/// Index of `GS` in `env.segs`.
const R_GS: usize = 5;

impl ArchAdapter for Amd64 {
    /// Returns the RAM of the `pc-i440fx-*` and `pc-q35-*` machines.
    ///
    /// The `pc.ram` block starts at guest physical address 0. The part that
    /// does not fit below the PCI hole continues at 4 GiB (`pc_memory_init`
    /// in `hw/i386/pc.c`).
    ///
    /// # Notes
    ///
    /// The split assumes the default of the `max-ram-below-4g` machine
    /// property. With an AMD vCPU, QEMU moves the RAM above 4 GiB to 1 TiB
    /// when the RAM and the device memory reach the HyperTransport hole at
    /// 1012 GiB. The stream records neither, so such machines read wrong.
    fn ram_ranges(machine: &str, blocks: &[(&str, u64)]) -> Result<Vec<RamRange>, Error> {
        // RAM of `threshold` bytes or more is split at `lowmem`. Smaller RAM
        // lies below 4 GiB as a whole.
        let (threshold, lowmem) = if machine.starts_with("pc-i440fx-") {
            // `pc_init1` in `hw/i386/pc_piix.c` splits 3.5 GiB of RAM or more
            // at 3 GiB, the `gigabyte_align` limit. Only machine types up to
            // 1.7 lack `gigabyte_align`. QEMU writes no VM description for
            // machine types before 2.3 (QEMU commit 54ed388b29).
            (0xe000_0000, 0xc000_0000)
        }
        else if machine.starts_with("pc-q35-") {
            // `pc_q35_init` in `hw/i386/pc_q35.c` splits 2.75 GiB of RAM or
            // more at 2 GiB.
            (0xb000_0000, 0x8000_0000)
        }
        else {
            return Err(Error::UnsupportedMachine {
                machine: machine.into(),
            });
        };

        let ram_size = block_length(blocks, PC_RAM)?;
        let below_4g_mem_size = if ram_size >= threshold {
            lowmem
        }
        else {
            ram_size
        };

        let mut ranges = vec![RamRange {
            block: PC_RAM,
            offset: 0,
            address: 0,
            length: below_4g_mem_size,
        }];

        if ram_size > below_4g_mem_size {
            ranges.push(RamRange {
                block: PC_RAM,
                offset: below_4g_mem_size,
                address: ABOVE_4G_MEM_START,
                length: ram_size - below_4g_mem_size,
            });
        }

        Ok(ranges)
    }

    /// Builds the registers from a `cpu` section of `vmstate_x86_cpu`
    /// (`target/i386/machine.c`).
    ///
    /// qemu-system-x86_64 saves 16 general-purpose registers and the
    /// `target_ulong` fields with 8 bytes. qemu-system-i386 saves 8
    /// registers and these fields with 4 bytes, and it has no `STAR`,
    /// `LSTAR`, `CSTAR`, `FMASK` and `KernelGSbase` fields. Missing
    /// registers read as zero.
    fn registers(cpu: &CpuState) -> Result<Self::Registers, Error> {
        // `env.regs` follows `R_EAX` to `R_R15` in `target/i386/cpu.h`.
        let count = cpu.count("env.regs").unwrap_or_default();
        let reg = |index: usize| {
            if index < count {
                cpu.uint("env.regs", index)
            }
            else {
                Ok(0)
            }
        };

        Ok(Registers {
            rax: reg(0)?,
            rbx: reg(3)?,
            rcx: reg(1)?,
            rdx: reg(2)?,
            rbp: reg(5)?,
            rsi: reg(6)?,
            rdi: reg(7)?,
            rsp: reg(4)?,
            r8: reg(8)?,
            r9: reg(9)?,
            r10: reg(10)?,
            r11: reg(11)?,
            r12: reg(12)?,
            r13: reg(13)?,
            r14: reg(14)?,
            r15: reg(15)?,
            rip: cpu.uint("env.eip", 0)?,
            rflags: Rflags(cpu.uint("env.eflags", 0)?),

            cr0: Cr0(cpu.uint("env.cr[0]", 0)?),
            cr2: Cr2(cpu.uint("env.cr[2]", 0)?),
            cr3: Cr3(cpu.uint("env.cr[3]", 0)?),
            cr4: Cr4(cpu.uint("env.cr[4]", 0)?),

            dr0: Dr0(cpu.uint("env.dr", 0)?),
            dr1: Dr1(cpu.uint("env.dr", 1)?),
            dr2: Dr2(cpu.uint("env.dr", 2)?),
            dr3: Dr3(cpu.uint("env.dr", 3)?),
            dr6: Dr6(cpu.uint("env.dr", 6)?),
            dr7: Dr7(cpu.uint("env.dr", 7)?),

            cs: segment(cpu, "env.segs", R_CS)?,
            ds: segment(cpu, "env.segs", R_DS)?,
            es: segment(cpu, "env.segs", R_ES)?,
            fs: segment(cpu, "env.segs", R_FS)?,
            gs: segment(cpu, "env.segs", R_GS)?,
            ss: segment(cpu, "env.segs", R_SS)?,
            tr: segment(cpu, "env.tr", 0)?,
            ldtr: segment(cpu, "env.ldt", 0)?,

            // QEMU keeps the descriptor table registers in segment structs,
            // with the selector and the flags unused.
            idtr: Idtr {
                base: cpu.member("env.idt", 0, "base")?,
                limit: cpu.member("env.idt", 0, "limit")? as u32,
            },
            gdtr: Gdtr {
                base: cpu.member("env.gdt", 0, "base")?,
                limit: cpu.member("env.gdt", 0, "limit")? as u32,
            },

            sysenter_cs: cpu.uint("env.sysenter_cs", 0)?,
            sysenter_esp: cpu.uint("env.sysenter_esp", 0)?,
            sysenter_eip: cpu.uint("env.sysenter_eip", 0)?,
            shadow_gs: optional(cpu, "env.kernelgsbase")?,

            msr_flags: 0,
            msr_lstar: optional(cpu, "env.lstar")?,
            msr_star: optional(cpu, "env.star")?,
            msr_cstar: optional(cpu, "env.cstar")?,
            msr_syscall_mask: optional(cpu, "env.fmask")?,
            msr_efer: MsrEfer(efer(cpu)?),
            msr_tsc_aux: cpu.uint("env.tsc_aux", 0)?,
        })
    }
}

/// Returns a field that only qemu-system-x86_64 saves, or zero.
fn optional(cpu: &CpuState, field: &str) -> Result<u64, Error> {
    match cpu.count(field) {
        Some(_) => cpu.uint(field, 0),
        None => Ok(0),
    }
}

/// Returns `EFER`.
///
/// qemu-system-x86_64 saves `env.efer` in the section itself.
/// qemu-system-i386 saves it in the `cpu/efer32` subsection, and only when it
/// is not zero.
fn efer(cpu: &CpuState) -> Result<u64, Error> {
    if cpu.count("env.efer").is_some() {
        return cpu.uint("env.efer", 0);
    }

    match cpu.subsection("cpu/efer32") {
        Some(efer32) => efer32.uint("env.efer", 0),
        None => Ok(0),
    }
}

/// Reads a segment register from an element of a field of segment structs
/// (`vmstate_segment` in `target/i386/machine.c`).
fn segment(cpu: &CpuState, field: &str, index: usize) -> Result<SegmentDescriptor, Error> {
    // The flags hold the high doubleword of the descriptor, with the type in
    // bits 8 to 11, S in bit 12, DPL in bits 13 and 14, P in bit 15, AVL in
    // bit 20, L in bit 21, D/B in bit 22 and G in bit 23 (`DESC_*_SHIFT` in
    // `target/i386/cpu.h`). `SegmentAccess` holds the same bits in bits 0
    // to 11.
    let flags = cpu.member(field, index, "flags")?;
    let access = ((flags >> 8) & 0xff) | ((flags >> 12) & 0xf00);

    Ok(SegmentDescriptor {
        base: cpu.member(field, index, "base")?,
        limit: cpu.member(field, index, "limit")? as u32,
        selector: Selector(cpu.member(field, index, "selector")? as u16),
        access: SegmentAccess(access as u32),
    })
}
