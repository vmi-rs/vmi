<!-- readme start -->
VMI driver for QEMU ELF core dumps.

Reads guest physical memory from the `PT_LOAD` segments of a core dump
created by the QEMU `dump-guest-memory` command, in ELF format. Each
segment maps `p_paddr` to its file data, and memory not covered by any
segment cannot be read. Pages that are only partially covered read as
zero in the holes.

Each `NT_PRSTATUS` note describes one vCPU in note order, with `pr_pid`
equal to the vCPU index plus one. The note carries the general-purpose
registers only, so the system registers are read from a separate JSON
register file.

# Register file

The register file is a JSON object with one entry per vCPU, keyed by
`cpu<index>`. Each entry holds a `regs` object that maps register names to
`0x`-prefixed hexadecimal strings. Other members of an entry, such as
`state`, are ignored, and so are registers that the architecture does not
use.

```json
{
  "cpu0": {
    "state": "running",
    "regs": {
      "x30": "0xfffffe002c7e5414",
      "sp": "0xfffffe6e9ff9bfc0",
      "pc": "0xfffffe002c7e5434",
      "TTBR1_EL1": "0x73f88000",
      "TCR_EL1": "0x800226511a511"
    }
  }
}
```

For ARM64, the register file must provide `pc`, `sp`, `x30`, `SP_EL0`,
`SP_EL1`, `TTBR0_EL1`, `TTBR1_EL1`, `TCR_EL1`, `SCTLR_EL1`, `MAIR_EL1`,
`VBAR_EL1`, `CONTEXTIDR_EL1`, `ELR_EL1`, `SPSR_EL1`, `ESR_EL1`, `FAR_EL1`,
`TPIDR_EL0`, `TPIDR_EL1` and `TPIDRRO_EL0`. The values of `pc`, `sp` and
`x30` must equal the values of the `NT_PRSTATUS` note, which guards
against pairing a register file with the wrong dump. `TCR_EL1` must match
the paging geometry of the architecture. The `sp` of the note replaces
the stack pointer bank selected by `pstate`.
<!-- readme end -->
