# AArch64 Architecture Support — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AArch64 (ARM64) architecture support to vmi-rs, enabling VMI on arm64 KVM guests.

**Architecture:** New `vmi-arch-aarch64` crate implementing the `Architecture` trait with ARM64-specific types (registers, paging, events, interrupts). A new `aarch64` adapter module in `vmi-driver-kvm` bridges KVM ring events to the architecture types. Workspace integration via Cargo features mirrors the existing `arch-amd64` pattern.

**Tech Stack:** Rust (edition 2024), zerocopy, bitflags, smallvec, vmi-core traits, kvm crate (libkvm)

**Spec:** `docs/superpowers/specs/2026-03-17-aarch64-architecture-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `crates/vmi-arch-aarch64/Cargo.toml` | Crate manifest with bitflags, smallvec, zerocopy, vmi-core deps |
| `crates/vmi-arch-aarch64/src/lib.rs` | `Aarch64` struct, `Architecture` impl, `Registers` trait impl, `EventReason` trait impl, re-exports |
| `crates/vmi-arch-aarch64/src/registers.rs` | `Registers`, `GpRegisters`, `Pstate` types |
| `crates/vmi-arch-aarch64/src/paging.rs` | `PageTableLevel`, `PageTableEntry` types |
| `crates/vmi-arch-aarch64/src/translation.rs` | `TranslationEntry`, `TranslationEntries`, `VaTranslation` |
| `crates/vmi-arch-aarch64/src/event.rs` | `EventMonitor`, `EventReason`, event data structs |
| `crates/vmi-arch-aarch64/src/interrupt.rs` | `Interrupt`, `SyncException`, ESR encoding |
| `crates/vmi-arch-aarch64/src/address.rs` | `ttbr_to_pa`, `ttbr_to_gfn` conversions |
| `crates/vmi-driver-kvm/src/arch/aarch64/mod.rs` | `ArchAdapter` impl for `Aarch64` |
| `crates/vmi-driver-kvm/src/arch/aarch64/registers.rs` | `kvm_vmi_regs` ↔ `Registers` conversion |
| `crates/vmi-driver-kvm/src/arch/aarch64/event.rs` | `KvmVmiEventReason` → `EventReason` mapping |
| `examples/kvm-basic-aarch64.rs` | Minimal arm64 VMI example |

### Modified Files

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Add `vmi-arch-aarch64` workspace dep, optional dep, feature, default feature, dev-dep, example entry |
| `src/lib.rs` | Add `arch::aarch64` module behind `cfg(feature = "arch-aarch64")` |
| `crates/vmi-driver-kvm/Cargo.toml` | Add `vmi-arch-aarch64` dep gated on `cfg(target_arch = "aarch64")` |
| `crates/vmi-driver-kvm/src/lib.rs` | Remove x86_64 cfg gate from `mod convert;` import, add aarch64 convert use |
| `crates/vmi-driver-kvm/src/driver.rs:19` | Update `monitor` field cfg_attr to include aarch64 |
| `crates/vmi-driver-kvm/src/arch/mod.rs` | Add `cfg(target_arch = "aarch64") mod aarch64;` |

---

## Chunk 1: `vmi-arch-aarch64` Crate — Core Types

### Task 1: Scaffold the Crate

**Files:**
- Create: `crates/vmi-arch-aarch64/Cargo.toml`
- Create: `crates/vmi-arch-aarch64/src/lib.rs`

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "vmi-arch-aarch64"
version = { workspace = true }
license = { workspace = true }
authors = { workspace = true }
edition = { workspace = true }
publish = { workspace = true }
rust-version = { workspace = true }

homepage = { workspace = true }
repository = { workspace = true }
description = "AArch64 architecture specific code for VMI"
keywords = [
    "vmi",
    "aarch64",
    "arm64",
]

[lints]
workspace = true

[dependencies]
bitflags = { workspace = true }
smallvec = { workspace = true, features = ["union"] }
zerocopy = { workspace = true, features = ["derive"] }

vmi-core = { workspace = true }
```

- [ ] **Step 2: Create minimal `lib.rs` stub**

```rust
//! AArch64 architecture definitions.

mod address;
mod event;
mod interrupt;
mod paging;
mod registers;
mod translation;

/// AArch64 architecture.
#[derive(Debug)]
pub struct Aarch64;
```

This won't compile yet — the modules don't exist. Create empty files for each module:

- [ ] **Step 3: Create empty module files**

Create each of these files with just a comment:
- `crates/vmi-arch-aarch64/src/address.rs` — empty
- `crates/vmi-arch-aarch64/src/event.rs` — empty
- `crates/vmi-arch-aarch64/src/interrupt.rs` — empty
- `crates/vmi-arch-aarch64/src/paging.rs` — empty
- `crates/vmi-arch-aarch64/src/registers.rs` — empty
- `crates/vmi-arch-aarch64/src/translation.rs` — empty

- [ ] **Step 4: Verify the crate compiles**

Run: `cargo check -p vmi-arch-aarch64`
Expected: compiles with warnings about unused modules

- [ ] **Step 5: Commit**

```bash
git add crates/vmi-arch-aarch64/
git commit -m "feat(vmi-arch-aarch64): scaffold new crate"
```

---

### Task 2: Registers and Pstate

**Files:**
- Modify: `crates/vmi-arch-aarch64/src/registers.rs`

- [ ] **Step 1: Implement `Pstate`, `Registers`, and `GpRegisters`**

Write `registers.rs`:

```rust
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p vmi-arch-aarch64`
Expected: compiles (warnings about unused items OK)

- [ ] **Step 3: Commit**

```bash
git add crates/vmi-arch-aarch64/src/registers.rs
git commit -m "feat(vmi-arch-aarch64): add Registers, GpRegisters, Pstate types"
```

---

### Task 3: Paging Types

**Files:**
- Modify: `crates/vmi-arch-aarch64/src/paging.rs`

- [ ] **Step 1: Implement `PageTableLevel` and `PageTableEntry`**

Write `paging.rs`:

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{Gfn, Pa};

/// The levels in the AArch64 page table hierarchy (4KB granule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Page Table (L3) — 4KB pages.
    L3,
    /// Page Middle Directory (L2) — 2MB blocks possible.
    L2,
    /// Page Upper Directory (L1) — 1GB blocks possible.
    L1,
    /// Page Global Directory (L0) — 512GB region.
    L0,
}

impl PageTableLevel {
    /// Returns the next lower level in the page table hierarchy.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::L3 => None,
            Self::L2 => Some(Self::L3),
            Self::L1 => Some(Self::L2),
            Self::L0 => Some(Self::L1),
        }
    }

    /// Returns the next higher level in the page table hierarchy.
    pub fn previous(self) -> Option<Self> {
        match self {
            Self::L3 => Some(Self::L2),
            Self::L2 => Some(Self::L1),
            Self::L1 => Some(Self::L0),
            Self::L0 => None,
        }
    }
}

/// A page table entry (descriptor) in the AArch64 paging structures.
#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Checks if the descriptor is valid (bit 0).
    pub fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if this is a table descriptor (bits [1:0] == 0b11).
    /// Only meaningful at L0-L2.
    pub fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Checks if this is a block descriptor (bits [1:0] == 0b01).
    /// Only meaningful at L1/L2.
    pub fn is_block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Checks if this is a page descriptor (bits [1:0] == 0b11 at L3).
    /// Same encoding as table but at leaf level.
    pub fn is_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Extracts the output address (bits [47:12]) as a physical address.
    pub fn output_address(self) -> Pa {
        Pa(self.0 & 0x0000_FFFF_FFFF_F000)
    }

    /// Extracts the page frame number from the output address.
    pub fn pfn(self) -> Gfn {
        Gfn::new(self.output_address().0 >> 12)
    }

    /// Access flag (bit 10).
    pub fn af(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Access permission bits [7:6].
    pub fn ap(self) -> u8 {
        ((self.0 >> 6) & 0x3) as u8
    }

    /// Execute-never for EL0 / UXN (bit 54).
    pub fn xn(self) -> bool {
        (self.0 >> 54) & 1 != 0
    }

    /// Privileged execute-never / PXN (bit 53).
    pub fn pxn(self) -> bool {
        (self.0 >> 53) & 1 != 0
    }
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("valid", &self.valid())
            .field("is_table", &self.is_table())
            .field("is_block", &self.is_block())
            .field("af", &self.af())
            .field("ap", &self.ap())
            .field("xn", &self.xn())
            .field("pxn", &self.pxn())
            .field("pfn", &self.pfn())
            .finish()
    }
}
```

Note: `Gfn` is used via `crate::Gfn` which comes from `vmi_core` re-export. We need to make sure `lib.rs` imports it. We'll handle that in a later task when we wire up the `Architecture` impl.

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p vmi-arch-aarch64`
Expected: May fail because `crate::Gfn` isn't available yet. That's fine — we'll fix the import when we wire up `lib.rs` in Task 6.

For now, temporarily change `use crate::Gfn;` to `use vmi_core::Gfn;` to verify the file compiles in isolation. Then change it back after Task 6.

- [ ] **Step 3: Commit**

```bash
git add crates/vmi-arch-aarch64/src/paging.rs
git commit -m "feat(vmi-arch-aarch64): add PageTableLevel and PageTableEntry"
```

---

### Task 4: Translation Types

**Files:**
- Modify: `crates/vmi-arch-aarch64/src/translation.rs`

- [ ] **Step 1: Implement translation types**

Write `translation.rs`. Follow the amd64 pattern exactly — same struct shape, different `PageTableLevel` and `PageTableEntry` types:

```rust
use smallvec::SmallVec;

use super::{PageTableEntry, PageTableLevel};
use crate::Pa;

/// A single entry in the page table hierarchy during virtual address
/// translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationEntry {
    /// The level of the page table hierarchy this entry belongs to.
    pub level: PageTableLevel,

    /// The actual page table entry.
    pub entry: PageTableEntry,

    /// The physical address where this entry is located in memory.
    pub entry_address: Pa,
}

impl TranslationEntry {
    /// Checks if the entry is a leaf node in the page table hierarchy.
    pub fn is_leaf(&self) -> bool {
        self.entry.valid()
            && match self.level {
                PageTableLevel::L3 => self.entry.is_page(),
                PageTableLevel::L2 => self.entry.is_block(),
                PageTableLevel::L1 => self.entry.is_block(),
                PageTableLevel::L0 => false, // L0 cannot be a block with 4KB granule
            }
    }
}

/// Collection of translation entries, typically used in page table walks.
pub type TranslationEntries = SmallVec<[TranslationEntry; 4]>;

/// The result of a virtual address translation process.
#[derive(Debug)]
pub struct VaTranslation {
    /// The page table entries traversed during the translation process.
    pub(super) entries: TranslationEntries,

    /// The physical address if translation was successful.
    pub(super) pa: Option<Pa>,
}

impl VaTranslation {
    /// Returns the page table entries traversed during the translation.
    pub fn entries(&self) -> &[TranslationEntry] {
        &self.entries
    }

    /// Consumes the `VaTranslation` and returns the `TranslationEntries`.
    pub fn into_entries(self) -> TranslationEntries {
        self.entries
    }

    /// Returns the physical address if translation was successful.
    pub fn pa(&self) -> Option<Pa> {
        self.pa
    }

    /// Checks if all page table entries in the translation path are valid.
    pub fn valid(&self) -> bool {
        self.entries.iter().all(|entry| entry.entry.valid())
    }
}

impl IntoIterator for VaTranslation {
    type Item = TranslationEntry;
    type IntoIter = <TranslationEntries as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
```

Note: Uses `crate::Pa` which will be available via `vmi_core` re-export from `lib.rs`. Same as paging — temporarily use `vmi_core::Pa` if needed, fix when wiring up lib.rs.

- [ ] **Step 2: Commit**

```bash
git add crates/vmi-arch-aarch64/src/translation.rs
git commit -m "feat(vmi-arch-aarch64): add VaTranslation and TranslationEntry types"
```

---

### Task 5: Events, Interrupts, and Address Utilities

**Files:**
- Modify: `crates/vmi-arch-aarch64/src/event.rs`
- Modify: `crates/vmi-arch-aarch64/src/interrupt.rs`
- Modify: `crates/vmi-arch-aarch64/src/address.rs`

- [ ] **Step 1: Implement event types**

Write `event.rs`:

```rust
use vmi_core::{Gfn, MemoryAccess, Pa, Va};

use crate::SystemRegister;

/// Event generated when monitored memory is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess {
    /// Physical address that was accessed.
    pub pa: Pa,

    /// Virtual address that was accessed.
    pub va: Va,

    /// Type of access that occurred (read/write/execute).
    pub access: MemoryAccess,
}

/// BRK software breakpoint event.
#[derive(Debug, Clone, Copy)]
pub struct EventBreakpoint {
    /// GFN of the breakpoint instruction (gpa >> PAGE_SHIFT).
    pub gfn: Gfn,
    /// Program counter at the breakpoint.
    pub pc: Va,
    /// Immediate value from BRK #imm16.
    pub comment: u16,
}

/// System register write event.
#[derive(Debug, Clone, Copy)]
pub struct EventSysreg {
    /// Which system register was written.
    pub register: SystemRegister,
    /// Value before the write.
    pub old_value: u64,
    /// Value the guest is writing.
    pub new_value: u64,
}

/// Single-step completion event.
#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep {
    /// GFN of the instruction.
    pub gfn: Gfn,
}

/// Reason for an event.
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    /// Memory access event (read/write/execute).
    MemoryAccess(EventMemoryAccess),
    /// BRK software breakpoint event.
    Breakpoint(EventBreakpoint),
    /// System register write event.
    Sysreg(EventSysreg),
    /// Single-step completion event.
    Singlestep(EventSinglestep),
}

impl EventReason {
    /// Returns the memory access event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a memory access event.
    pub fn as_memory_access(&self) -> &EventMemoryAccess {
        match self {
            Self::MemoryAccess(memory_access) => memory_access,
            _ => panic!("EventReason is not a MemoryAccess"),
        }
    }

    /// Returns the breakpoint event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a breakpoint event.
    pub fn as_breakpoint(&self) -> &EventBreakpoint {
        match self {
            Self::Breakpoint(breakpoint) => breakpoint,
            _ => panic!("EventReason is not a Breakpoint"),
        }
    }

    /// Returns the sysreg event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a sysreg event.
    pub fn as_sysreg(&self) -> &EventSysreg {
        match self {
            Self::Sysreg(sysreg) => sysreg,
            _ => panic!("EventReason is not a Sysreg"),
        }
    }

    /// Returns the singlestep event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a singlestep event.
    pub fn as_singlestep(&self) -> &EventSinglestep {
        match self {
            Self::Singlestep(singlestep) => singlestep,
            _ => panic!("EventReason is not a Singlestep"),
        }
    }
}

/// Specifies which hardware events should be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor BRK software breakpoints.
    Breakpoint,
    /// Monitor system register writes.
    Sysreg(SystemRegister),
    /// Monitor single-step completion.
    Singlestep,
}

/// System registers that can be monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    /// System Control Register EL1.
    SctlrEl1,
    /// Translation Table Base Register 0 EL1.
    Ttbr0El1,
    /// Translation Table Base Register 1 EL1.
    Ttbr1El1,
    /// Translation Control Register EL1.
    TcrEl1,
}
```

- [ ] **Step 2: Implement interrupt types**

Write `interrupt.rs`:

```rust
/// Interrupt injection types for AArch64.
#[derive(Debug, Clone, Copy)]
pub enum Interrupt {
    /// Synchronous exception — encoded as full ESR value.
    Sync(SyncException),
    /// Asynchronous SError — ISS portion only.
    SError {
        /// Instruction Specific Syndrome bits.
        iss: u32,
    },
}

/// Synchronous exception types.
#[derive(Debug, Clone, Copy)]
pub enum SyncException {
    /// Data abort (EC=0x24 same EL, EC=0x25 lower EL).
    DataAbort {
        /// Instruction Specific Syndrome bits.
        iss: u32,
        /// Instruction Length. true = 32-bit instruction.
        il: bool,
    },
    /// Instruction abort (EC=0x20 same EL, EC=0x21 lower EL).
    InstructionAbort {
        /// Instruction Specific Syndrome bits.
        iss: u32,
        /// Instruction Length.
        il: bool,
    },
    /// BRK instruction (EC=0x3C).
    Brk {
        /// Immediate value from BRK #imm16.
        comment: u16,
    },
    /// SVC instruction (EC=0x15).
    Svc {
        /// Immediate value from SVC #imm16.
        imm16: u16,
    },
    /// HVC instruction (EC=0x16).
    Hvc {
        /// Immediate value from HVC #imm16.
        imm16: u16,
    },
    /// Raw ESR value for other exception classes.
    Raw {
        /// Full ESR value.
        esr: u64,
    },
}

impl SyncException {
    /// Encode this exception as an ESR_EL2 value.
    pub fn to_esr(self) -> u64 {
        match self {
            Self::DataAbort { iss, il: true } => (0x25u64 << 26) | (1 << 25) | iss as u64,
            Self::DataAbort { iss, il: false } => (0x24u64 << 26) | iss as u64,
            Self::InstructionAbort { iss, il: true } => (0x21u64 << 26) | (1 << 25) | iss as u64,
            Self::InstructionAbort { iss, il: false } => (0x20u64 << 26) | iss as u64,
            Self::Brk { comment } => (0x3Cu64 << 26) | (1 << 25) | comment as u64,
            Self::Svc { imm16 } => (0x15u64 << 26) | (1 << 25) | imm16 as u64,
            Self::Hvc { imm16 } => (0x16u64 << 26) | (1 << 25) | imm16 as u64,
            Self::Raw { esr } => esr,
        }
    }
}
```

- [ ] **Step 3: Implement address utilities**

Write `address.rs`:

```rust
use vmi_core::{Architecture as _, Gfn, Pa};

use crate::Aarch64;

/// Extract the base address from a TTBR value.
///
/// Masks out ASID bits [63:48] and CnP bit [0].
pub fn ttbr_to_pa(ttbr: u64) -> Pa {
    Pa(ttbr & 0x0000_FFFF_FFFF_F000)
}

/// Extract the guest frame number from a TTBR value.
pub fn ttbr_to_gfn(ttbr: u64) -> Gfn {
    Aarch64::gfn_from_pa(ttbr_to_pa(ttbr))
}
```

- [ ] **Step 4: Commit**

```bash
git add crates/vmi-arch-aarch64/src/event.rs crates/vmi-arch-aarch64/src/interrupt.rs crates/vmi-arch-aarch64/src/address.rs
git commit -m "feat(vmi-arch-aarch64): add event, interrupt, and address types"
```

---

### Task 6: Wire Up lib.rs — Architecture Impl and Trait Impls

**Files:**
- Modify: `crates/vmi-arch-aarch64/src/lib.rs`

This is the largest single file. It contains the `Architecture` impl, `Registers` trait impl, event trait impls, `translate_address`, and the `translation()` method.

- [ ] **Step 1: Write the complete `lib.rs`**

```rust
//! AArch64 architecture definitions.

mod address;
mod event;
mod interrupt;
mod paging;
mod registers;
mod translation;

use vmi_core::{
    AccessContext, AddressContext, Architecture, Gfn, MemoryAccess, Pa, Va, VmiCore, VmiError,
    driver::VmiRead,
};
use zerocopy::FromBytes;

pub use self::{
    address::{ttbr_to_gfn, ttbr_to_pa},
    event::{
        EventBreakpoint, EventMemoryAccess, EventMonitor, EventReason, EventSinglestep,
        EventSysreg, SystemRegister,
    },
    interrupt::{Interrupt, SyncException},
    paging::{PageTableEntry, PageTableLevel},
    registers::{GpRegisters, Pstate, Registers},
    translation::{TranslationEntries, TranslationEntry, VaTranslation},
};

/// AArch64 architecture.
#[derive(Debug)]
pub struct Aarch64;

impl Architecture for Aarch64 {
    const PAGE_SIZE: u64 = 0x1000;
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xFFFF_FFFF_FFFF_F000;

    // BRK #0 = 0xD4200000 in little-endian.
    const BREAKPOINT: &'static [u8] = &[0x00, 0x00, 0x20, 0xD4];

    type Registers = Registers;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = SystemRegister;

    type EventMonitor = EventMonitor;
    type EventReason = EventReason;

    fn gfn_from_pa(pa: Pa) -> Gfn {
        Gfn(pa.0 >> Self::PAGE_SHIFT)
    }

    fn pa_from_gfn(gfn: Gfn) -> Pa {
        Pa(gfn.0 << Self::PAGE_SHIFT)
    }

    fn pa_offset(pa: Pa) -> u64 {
        pa.0 & !Self::PAGE_MASK
    }

    fn va_align_down(va: Va) -> Va {
        Self::va_align_down_for(va, PageTableLevel::L3)
    }

    fn va_align_down_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = match level {
            PageTableLevel::L3 => !0xFFFu64,
            PageTableLevel::L2 => !0x1F_FFFFu64,
            PageTableLevel::L1 => !0x3FFF_FFFFu64,
            PageTableLevel::L0 => !0x7F_FFFF_FFFFu64,
        };

        va & mask
    }

    fn va_align_up(va: Va) -> Va {
        Self::va_align_up_for(va, PageTableLevel::L3)
    }

    fn va_align_up_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = match level {
            PageTableLevel::L3 => 0xFFF,
            PageTableLevel::L2 => 0x1F_FFFF,
            PageTableLevel::L1 => 0x3FFF_FFFF,
            PageTableLevel::L0 => 0x7F_FFFF_FFFF,
        };

        (va + mask) & !mask
    }

    fn va_offset(va: Va) -> u64 {
        Self::va_offset_for(va, PageTableLevel::L3)
    }

    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            PageTableLevel::L3 => va.0 & 0xFFF,
            PageTableLevel::L2 => va.0 & 0x1F_FFFF,
            PageTableLevel::L1 => va.0 & 0x3FFF_FFFF,
            PageTableLevel::L0 => va.0 & 0x7F_FFFF_FFFF,
        }
    }

    fn va_index(va: Va) -> u64 {
        Self::va_index_for(va, PageTableLevel::L3)
    }

    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            PageTableLevel::L3 => (va.0 >> 12) & 0x1FF,
            PageTableLevel::L2 => (va.0 >> 21) & 0x1FF,
            PageTableLevel::L1 => (va.0 >> 30) & 0x1FF,
            PageTableLevel::L0 => (va.0 >> 39) & 0x1FF,
        }
    }

    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        // L0 (PGD)
        let buffer = vmi.read_page(Self::gfn_from_pa(root))?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l0i = Self::va_index_for(va, PageTableLevel::L0) as usize;
        let l0e = page_table[l0i];

        if !l0e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }
        // L0 cannot be a block descriptor with 4KB granule.

        // L1 (PUD)
        let buffer = vmi.read_page(l0e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l1i = Self::va_index_for(va, PageTableLevel::L1) as usize;
        let l1e = page_table[l1i];

        if !l1e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }

        if l1e.is_block() {
            return Ok(
                Self::pa_from_gfn(l1e.pfn()) + Self::va_offset_for(va, PageTableLevel::L1)
            );
        }

        // L2 (PMD)
        let buffer = vmi.read_page(l1e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l2i = Self::va_index_for(va, PageTableLevel::L2) as usize;
        let l2e = page_table[l2i];

        if !l2e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }

        if l2e.is_block() {
            return Ok(
                Self::pa_from_gfn(l2e.pfn()) + Self::va_offset_for(va, PageTableLevel::L2)
            );
        }

        // L3 (PTE)
        let buffer = vmi.read_page(l2e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l3i = Self::va_index_for(va, PageTableLevel::L3) as usize;
        let l3e = page_table[l3i];

        if !l3e.valid() || !l3e.is_page() {
            return Err(VmiError::page_fault((va, root)));
        }

        Ok(Self::pa_from_gfn(l3e.pfn()) + Self::va_offset_for(va, PageTableLevel::L3))
    }
}

impl Aarch64 {
    /// Performs a detailed page table walk returning all intermediate entries.
    pub fn translation<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> VaTranslation
    where
        Driver: VmiRead<Architecture = Self>,
    {
        let mut entries = TranslationEntries::new();

        // L0 (PGD)
        let buffer = match vmi.read_page(Self::gfn_from_pa(root)) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l0i = Self::va_index_for(va, PageTableLevel::L0) as usize;
        let l0e = page_table[l0i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L0,
            entry: l0e,
            entry_address: root + (l0i * size_of::<PageTableEntry>()) as u64,
        });

        if !l0e.valid() {
            return VaTranslation { entries, pa: None };
        }

        // L1 (PUD)
        let buffer = match vmi.read_page(l0e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l1i = Self::va_index_for(va, PageTableLevel::L1) as usize;
        let l1e = page_table[l1i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L1,
            entry: l1e,
            entry_address: Self::pa_from_gfn(l0e.pfn())
                + (l1i * size_of::<PageTableEntry>()) as u64,
        });

        if !l1e.valid() {
            return VaTranslation { entries, pa: None };
        }

        if l1e.is_block() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(l1e.pfn()) + Self::va_offset_for(va, PageTableLevel::L1),
                ),
            };
        }

        // L2 (PMD)
        let buffer = match vmi.read_page(l1e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l2i = Self::va_index_for(va, PageTableLevel::L2) as usize;
        let l2e = page_table[l2i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L2,
            entry: l2e,
            entry_address: Self::pa_from_gfn(l1e.pfn())
                + (l2i * size_of::<PageTableEntry>()) as u64,
        });

        if !l2e.valid() {
            return VaTranslation { entries, pa: None };
        }

        if l2e.is_block() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(l2e.pfn()) + Self::va_offset_for(va, PageTableLevel::L2),
                ),
            };
        }

        // L3 (PTE)
        let buffer = match vmi.read_page(l2e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l3i = Self::va_index_for(va, PageTableLevel::L3) as usize;
        let l3e = page_table[l3i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L3,
            entry: l3e,
            entry_address: Self::pa_from_gfn(l2e.pfn())
                + (l3i * size_of::<PageTableEntry>()) as u64,
        });

        VaTranslation {
            entries,
            pa: if l3e.valid() && l3e.is_page() {
                Some(Self::pa_from_gfn(l3e.pfn()) + Self::va_offset_for(va, PageTableLevel::L3))
            } else {
                None
            },
        }
    }
}

impl vmi_core::arch::GpRegisters for GpRegisters {}

impl vmi_core::arch::Registers for Registers {
    type Architecture = Aarch64;

    type GpRegisters = GpRegisters;

    fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.pc = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.sp
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.sp = sp;
    }

    fn result(&self) -> u64 {
        self.x[0]
    }

    fn set_result(&mut self, result: u64) {
        self.x[0] = result;
    }

    fn gp_registers(&self) -> GpRegisters {
        GpRegisters {
            x: self.x,
            sp: self.sp,
            pc: self.pc,
            pstate: self.pstate,
        }
    }

    fn set_gp_registers(&mut self, gp: &GpRegisters) {
        self.x = gp.x;
        self.sp = gp.sp;
        self.pc = gp.pc;
        self.pstate = gp.pstate;
    }

    fn address_width(&self) -> usize {
        8 // AArch64 is always 64-bit
    }

    fn effective_address_width(&self) -> usize {
        8 // AArch64 is always 64-bit
    }

    fn access_context(&self, va: Va) -> AccessContext {
        self.address_context(va).into()
    }

    fn address_context(&self, va: Va) -> AddressContext {
        (va, self.translation_root(va)).into()
    }

    fn translation_root(&self, va: Va) -> Pa {
        // Bit 55 selects TTBR: 1 = TTBR1 (kernel), 0 = TTBR0 (user).
        let ttbr = if va.0 & (1 << 55) != 0 {
            self.ttbr1_el1
        } else {
            self.ttbr0_el1
        };
        ttbr_to_pa(ttbr)
    }

    fn return_address<Driver>(&self, _vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
    {
        // ARM64 link register is x30.
        // Known limitation: non-leaf functions may have saved LR to stack.
        Ok(Va(self.x[30]))
    }
}

impl vmi_core::arch::EventMemoryAccess for EventMemoryAccess {
    type Architecture = Aarch64;

    fn pa(&self) -> Pa {
        self.pa
    }

    fn va(&self) -> Va {
        self.va
    }

    fn access(&self) -> MemoryAccess {
        self.access
    }
}

impl vmi_core::arch::EventInterrupt for EventBreakpoint {
    type Architecture = Aarch64;

    fn gfn(&self) -> Gfn {
        self.gfn
    }
}

impl vmi_core::arch::EventReason for EventReason {
    type Architecture = Aarch64;

    fn as_memory_access(
        &self,
    ) -> Option<&impl vmi_core::arch::EventMemoryAccess<Architecture = Aarch64>> {
        match self {
            EventReason::MemoryAccess(memory_access) => Some(memory_access),
            _ => None,
        }
    }

    fn as_interrupt(&self) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Aarch64>> {
        match self {
            EventReason::Breakpoint(breakpoint) => Some(breakpoint),
            _ => None,
        }
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Aarch64>> {
        match self {
            EventReason::Breakpoint(breakpoint) => Some(breakpoint),
            _ => None,
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p vmi-arch-aarch64`
Expected: PASS (all types connected, all trait impls satisfied)

- [ ] **Step 3: Commit**

```bash
git add crates/vmi-arch-aarch64/src/lib.rs
git commit -m "feat(vmi-arch-aarch64): implement Architecture trait and all trait impls"
```

---

## Chunk 2: `vmi-driver-kvm` AArch64 Adapter

### Task 7: Un-gate the Convert Module

**Files:**
- Modify: `crates/vmi-driver-kvm/src/lib.rs`
- Modify: `crates/vmi-driver-kvm/src/convert.rs` (no content change, just usage)

The `convert` module (`FromExt`, `IntoExt`, `TryFromExt`) is currently gated behind `cfg(target_arch = "x86_64")`. The aarch64 adapter needs these traits too.

- [ ] **Step 1: Remove the cfg gate from `mod convert`**

In `crates/vmi-driver-kvm/src/lib.rs`, change:
```rust
#[cfg(target_arch = "x86_64")]
mod convert;
```
to:
```rust
mod convert;
```

- [ ] **Step 2: Remove the cfg gate from the `use` import**

In the same file, change:
```rust
#[cfg(target_arch = "x86_64")]
use self::convert::{FromExt, IntoExt, TryFromExt};
```
to:
```rust
use self::convert::{FromExt, IntoExt, TryFromExt};
```

- [ ] **Step 3: Verify it compiles on the current architecture**

Run: `cargo check -p vmi-driver-kvm`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/vmi-driver-kvm/src/lib.rs
git commit -m "refactor(vmi-driver-kvm): un-gate convert module for multi-arch support"
```

---

### Task 8: Add aarch64 Module to arch/mod.rs

**Files:**
- Modify: `crates/vmi-driver-kvm/src/arch/mod.rs`

- [ ] **Step 1: Add the aarch64 module**

Add after the `#[cfg(target_arch = "x86_64")] mod amd64;` line:

```rust
#[cfg(target_arch = "aarch64")]
mod aarch64;
```

- [ ] **Step 2: Create the module directory and stub files**

Create empty files:
- `crates/vmi-driver-kvm/src/arch/aarch64/mod.rs`
- `crates/vmi-driver-kvm/src/arch/aarch64/registers.rs`
- `crates/vmi-driver-kvm/src/arch/aarch64/event.rs`

The `mod.rs` should initially contain:
```rust
mod event;
mod registers;
```

- [ ] **Step 3: Commit**

```bash
git add crates/vmi-driver-kvm/src/arch/
git commit -m "feat(vmi-driver-kvm): scaffold aarch64 arch adapter module"
```

---

### Task 9: Register Conversion

**Files:**
- Modify: `crates/vmi-driver-kvm/src/arch/aarch64/registers.rs`

- [ ] **Step 1: Implement register conversion**

Write `registers.rs`:

```rust
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

            // Not available in ring event
            vbar_el1: 0,
            tpidr_el1: 0,
            sp_el0: 0,
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
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add crates/vmi-driver-kvm/src/arch/aarch64/registers.rs
git commit -m "feat(vmi-driver-kvm): add aarch64 register conversion"
```

---

### Task 10: Event Mapping

**Files:**
- Modify: `crates/vmi-driver-kvm/src/arch/aarch64/event.rs`

- [ ] **Step 1: Implement event conversion**

Write `event.rs`:

```rust
use vmi_arch_aarch64::{
    EventBreakpoint, EventMemoryAccess, EventReason, EventSinglestep, EventSysreg, SystemRegister,
};
use vmi_core::{Gfn, Pa, Va};

use crate::TryFromExt;

impl TryFromExt<&kvm::KvmVmiEventReason> for EventReason {
    type Error = ();

    fn try_from_ext(value: &kvm::KvmVmiEventReason) -> Result<Self, Self::Error> {
        use kvm::KvmVmiEventReason;

        match *value {
            KvmVmiEventReason::MemoryAccess { gpa, access } => {
                Ok(Self::MemoryAccess(EventMemoryAccess {
                    pa: Pa(gpa),
                    va: Va(0),
                    access: vmi_core::MemoryAccess::from_bits_truncate(access as u8),
                }))
            }

            KvmVmiEventReason::Breakpoint { pc, gpa, comment } => {
                Ok(Self::Breakpoint(EventBreakpoint {
                    gfn: Gfn::new(gpa >> 12),
                    pc: Va(pc),
                    comment,
                }))
            }

            KvmVmiEventReason::Sysreg {
                reg,
                old_value,
                new_value,
            } => {
                let register = sysreg_from_index(reg)?;
                Ok(Self::Sysreg(EventSysreg {
                    register,
                    old_value,
                    new_value,
                }))
            }

            KvmVmiEventReason::Singlestep { gpa } => Ok(Self::Singlestep(EventSinglestep {
                gfn: Gfn::new(gpa >> 12),
            })),
        }
    }
}

/// Convert a KVM sysreg index to a `SystemRegister`.
fn sysreg_from_index(index: u32) -> Result<SystemRegister, ()> {
    match index {
        kvm::sys::KVM_VMI_ARM64_SYSREG_SCTLR_EL1 => Ok(SystemRegister::SctlrEl1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TTBR0_EL1 => Ok(SystemRegister::Ttbr0El1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TTBR1_EL1 => Ok(SystemRegister::Ttbr1El1),
        kvm::sys::KVM_VMI_ARM64_SYSREG_TCR_EL1 => Ok(SystemRegister::TcrEl1),
        _ => Err(()),
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add crates/vmi-driver-kvm/src/arch/aarch64/event.rs
git commit -m "feat(vmi-driver-kvm): add aarch64 event conversion"
```

---

### Task 11: ArchAdapter Implementation

**Files:**
- Modify: `crates/vmi-driver-kvm/src/arch/aarch64/mod.rs`

- [ ] **Step 1: Implement ArchAdapter for Aarch64**

Write the full `mod.rs`:

```rust
mod event;
mod registers;

use std::os::fd::RawFd;

use vmi_arch_aarch64::{Aarch64, EventMonitor, EventReason, Interrupt, SystemRegister};
use vmi_core::{
    Registers as _, VcpuId, View, VmiEvent, VmiEventAction, VmiEventFlags, VmiEventResponse,
};

use crate::{ArchAdapter, Error, IntoExt as _, KvmDriver, TryFromExt};

/// Build a `kvm_vmi_control_event` for a simple event (no param union).
fn make_ctrl(event: u32, enable: u32) -> kvm::sys::kvm_vmi_control_event {
    kvm::sys::kvm_vmi_control_event {
        event,
        enable,
        flags: 0,
        pad: 0,
        __bindgen_anon_1: kvm::sys::kvm_vmi_control_event__bindgen_ty_1::default(),
    }
}

impl ArchAdapter for Aarch64 {
    fn registers_from_ring(regs: &kvm::sys::kvm_vmi_regs) -> Self::Registers {
        regs.into_ext()
    }

    fn registers_to_ring(regs: &Self::Registers) -> kvm::sys::kvm_vmi_regs {
        regs.into_ext()
    }

    fn registers_from_vcpu(_vcpu_fd: RawFd) -> Result<Self::Registers, Error> {
        // On arm64, registers come from ring events, not vCPU fd ioctls.
        Err(Error::NotSupported)
    }

    fn monitor_enable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 1u32;

        let ctrl = match option {
            EventMonitor::Breakpoint => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_BREAKPOINT_EVAL, enable)
            }
            EventMonitor::Sysreg(_) => {
                // arm64 sysreg monitoring is controlled by HCR_EL2.TVM which
                // traps all system register writes at once.
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SYSREG_EVAL, enable)
            }
            EventMonitor::Singlestep => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable)
            }
        };

        driver.monitor.control_event(&ctrl)?;
        Ok(())
    }

    fn monitor_disable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 0u32;

        let ctrl = match option {
            EventMonitor::Breakpoint => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_BREAKPOINT_EVAL, enable)
            }
            EventMonitor::Sysreg(_) => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SYSREG_EVAL, enable)
            }
            EventMonitor::Singlestep => {
                make_ctrl(kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable)
            }
        };

        let _ = driver.monitor.control_event(&ctrl);
        Ok(())
    }

    fn inject_interrupt(
        driver: &KvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Interrupt,
    ) -> Result<(), Error> {
        let (typ, esr) = match interrupt {
            Interrupt::Sync(exc) => (kvm::sys::KVM_VMI_ARM64_INJECT_SYNC, exc.to_esr()),
            Interrupt::SError { iss } => (kvm::sys::KVM_VMI_ARM64_INJECT_SERROR, iss as u64),
        };
        Ok(driver
            .session
            .inject_event(u16::from(vcpu) as u32, typ, esr)?)
    }

    fn process_event(
        _driver: &KvmDriver<Self>,
        raw_event: &mut kvm::sys::kvm_vmi_ring_event,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error> {
        // Parse the raw ring event into a safe event.
        let kvm_event =
            unsafe { kvm::KvmVmiEvent::from_raw(raw_event) }.ok_or(Error::NotSupported)?;

        // Convert to VMI event reason.
        let vmi_reason =
            EventReason::try_from_ext(&kvm_event.reason).map_err(|()| Error::NotSupported)?;

        // Convert registers.
        let mut registers = Self::registers_from_ring(&raw_event.regs);

        // Build the VMI event.
        let view = Some(View(kvm_event.view_id as u16));
        let flags = VmiEventFlags::VCPU_PAUSED;
        let vcpu_id = VcpuId::from(kvm_event.vcpu_id as u16);

        let vmi_event = VmiEvent::new(vcpu_id, flags, view, registers, vmi_reason);

        // Call the user's handler.
        let vmi_response = handler(&vmi_event);

        // Build the ring response flags.
        let mut response_flags: u32 = kvm::sys::KVM_VMI_RESPONSE_CONTINUE;

        // Handle SET_REGS.
        if let Some(new_gp_regs) = &vmi_response.registers {
            registers.set_gp_registers(new_gp_regs);
            raw_event.regs = Self::registers_to_ring(&registers);
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SET_REGS;
        }

        // Handle SWITCH_VIEW.
        if let Some(new_view) = vmi_response.view {
            raw_event.view_id = new_view.0 as u32;
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
        }

        // Map VmiEventAction to KVM response flags.
        match vmi_response.action {
            VmiEventAction::Continue => {}
            VmiEventAction::Deny => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_DENY;
            }
            VmiEventAction::ReinjectInterrupt => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_REINJECT;
            }
            VmiEventAction::Singlestep => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP;
            }
            VmiEventAction::FastSinglestep => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP_FAST;
            }
            VmiEventAction::Emulate => {
                response_flags |= kvm::sys::KVM_VMI_RESPONSE_EMULATE;
            }
        }

        raw_event.response = response_flags;

        Ok(())
    }

    fn reset_state(driver: &KvmDriver<Self>) -> Result<(), Error> {
        let _ = driver.monitor_disable(EventMonitor::Breakpoint);
        let _ = driver.monitor_disable(EventMonitor::Sysreg(SystemRegister::SctlrEl1));
        let _ = driver.monitor_disable(EventMonitor::Singlestep);
        let _ = driver.monitor.control_event(&make_ctrl(
            kvm::sys::KVM_VMI_EVENT_MEM_ACCESS,
            0,
        ));

        // Switch all vCPUs back to view 0.
        let _ = driver.session.switch_view(0);

        // Destroy all views.
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
```

- [ ] **Step 2: Add `vmi-arch-aarch64` dependency to `vmi-driver-kvm/Cargo.toml`**

Add after the `[target.'cfg(target_arch = "x86_64")'.dependencies]` section:

```toml
[target.'cfg(target_arch = "aarch64")'.dependencies]
vmi-arch-aarch64 = { workspace = true }
```

- [ ] **Step 3: Update `driver.rs` cfg_attr on the `monitor` field**

In `crates/vmi-driver-kvm/src/driver.rs:19`, the `monitor` field has a dead_code suppression that only accounts for x86_64. Now aarch64 also uses `monitor`. Change:

```rust
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) monitor: KvmVmiMonitor,
```

to:

```rust
    #[cfg_attr(not(any(target_arch = "x86_64", target_arch = "aarch64")), allow(dead_code))]
    pub(crate) monitor: KvmVmiMonitor,
```

- [ ] **Step 4: Verify it compiles on the current architecture**

Run: `cargo check -p vmi-driver-kvm`
Expected: PASS (the aarch64 code is behind `#[cfg(target_arch = "aarch64")]` so it won't be compiled on x86_64, but we should verify the crate still compiles)

- [ ] **Step 5: Commit**

```bash
git add crates/vmi-driver-kvm/
git commit -m "feat(vmi-driver-kvm): implement aarch64 ArchAdapter"
```

---

## Chunk 3: Workspace Integration and Example

### Task 12: Workspace Cargo.toml Integration

**Files:**
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Add workspace dependency**

In the `[workspace.dependencies]` section, add after the `vmi-arch-amd64` line:

```toml
vmi-arch-aarch64 = { path = "./crates/vmi-arch-aarch64", version = "0.4.0" }
```

- [ ] **Step 2: Add optional dependency to root package**

In the `[dependencies]` section, add after the `vmi-arch-amd64` line:

```toml
vmi-arch-aarch64 = { workspace = true, optional = true }
```

- [ ] **Step 3: Add feature flag**

In the `[features]` section, add after the `arch-amd64` feature:

```toml
arch-aarch64 = [
    "vmi-arch-aarch64",
    "vmi-utils?/arch-aarch64"
]
```

Add `"arch-aarch64"` to the `default` feature list.

- [ ] **Step 4: Add dev-dependency**

In the `[dev-dependencies]` section, add after the `vmi-arch-amd64` line:

```toml
vmi-arch-aarch64 = { workspace = true }
```

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo check`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml
git commit -m "feat: add vmi-arch-aarch64 to workspace"
```

---

### Task 13: Root Crate Re-exports

**Files:**
- Modify: `src/lib.rs`

- [ ] **Step 1: Add aarch64 module to `arch` module**

In `src/lib.rs`, inside the `pub mod arch` block, add after the `amd64` module:

```rust
    #[cfg(feature = "arch-aarch64")]
    pub mod aarch64 {
        #![doc = include_str!("../docs/vmi-arch-aarch64.md")]

        pub use vmi_arch_aarch64::*;
    }
```

- [ ] **Step 2: Create the doc stub**

Create `docs/vmi-arch-aarch64.md` with content:

```markdown
AArch64 architecture support for VMI.
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs docs/vmi-arch-aarch64.md
git commit -m "feat: re-export vmi-arch-aarch64 from root crate"
```

---

### Task 14: Example — `kvm-basic-aarch64`

**Files:**
- Create: `examples/kvm-basic-aarch64.rs`
- Modify: `Cargo.toml` (add example entry)

- [ ] **Step 1: Write the example**

Create `examples/kvm-basic-aarch64.rs`. Reuse the `find_qemu_vm()` pattern from `kvm-basic.rs` but instantiate `VmiKvmDriver::<Aarch64>`:

```rust
use std::fs;
use std::os::fd::RawFd;

use vmi_arch_aarch64::Aarch64;
use vmi_core::{Architecture as _, Gfn, VcpuId, VmiCore};
use vmi_driver_kvm::VmiKvmDriver;

/// Discover QEMU process and its KVM fd layout from /proc.
///
/// Returns (pid, vm_fd, vcpu_fds).
fn find_qemu_vm() -> Result<(u32, RawFd, Vec<RawFd>), Box<dyn std::error::Error>> {
    let mut qemu_pid = None;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        let cmdline = match fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if cmdline.contains("qemu") {
            qemu_pid = Some(pid);
            break;
        }
    }

    let pid = qemu_pid.ok_or("no QEMU process found")?;
    eprintln!("Found QEMU pid: {pid}");

    let fd_dir = format!("/proc/{pid}/fd");
    let mut vm_fd_num = None;
    let mut vcpu_fds_nums: Vec<(u32, RawFd)> = Vec::new();

    for entry in fs::read_dir(&fd_dir)? {
        let entry = entry?;
        let fd_num: RawFd = match entry.file_name().to_string_lossy().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let link = match fs::read_link(entry.path()) {
            Ok(l) => l,
            Err(_) => continue,
        };

        let link_str = link.to_string_lossy();

        if link_str.contains("kvm-vm") && vm_fd_num.is_none() {
            vm_fd_num = Some(fd_num);
        } else if link_str.contains("kvm-vcpu:") && !link_str.contains("kvm-vcpu-stats") {
            if let Some(idx_str) = link_str.rsplit(':').next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    vcpu_fds_nums.push((idx, fd_num));
                }
            }
        }
    }

    let vm_fd_num = vm_fd_num.ok_or("no kvm-vm fd found")?;
    vcpu_fds_nums.sort_by_key(|(idx, _)| *idx);

    eprintln!(
        "VM fd: {vm_fd_num}, vCPU fds: {:?}",
        vcpu_fds_nums
            .iter()
            .map(|(idx, fd)| format!("vcpu:{idx}=fd{fd}"))
            .collect::<Vec<_>>()
    );

    let pidfd = unsafe {
        libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_int)
    } as RawFd;
    if pidfd < 0 {
        return Err(format!(
            "pidfd_open failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let dup_fd = |target_fd: RawFd| -> Result<RawFd, Box<dyn std::error::Error>> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_pidfd_getfd,
                pidfd as libc::c_int,
                target_fd as libc::c_int,
                0 as libc::c_uint,
            )
        } as RawFd;
        if fd < 0 {
            Err(format!(
                "pidfd_getfd(fd={target_fd}) failed: {}",
                std::io::Error::last_os_error()
            )
            .into())
        } else {
            Ok(fd)
        }
    };

    let vm_fd = dup_fd(vm_fd_num)?;
    let mut vcpu_fds = Vec::new();
    for &(_, fd_num) in &vcpu_fds_nums {
        vcpu_fds.push(dup_fd(fd_num)?);
    }

    unsafe { libc::close(pidfd) };

    eprintln!("Duplicated: vm_fd={vm_fd}, vcpu_fds={vcpu_fds:?}");

    Ok((pid, vm_fd, vcpu_fds))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_pid, vm_fd, vcpu_fds) = find_qemu_vm()?;
    let num_vcpus = vcpu_fds.len() as u32;

    // Create VMI driver.
    eprintln!("Creating VMI driver...");
    let driver = VmiKvmDriver::<Aarch64>::new(vm_fd, num_vcpus, vcpu_fds)?;
    eprintln!("VMI driver created successfully");
    let vmi = VmiCore::new(driver)?;

    // Pause the VM and read basic info.
    let _pause_guard = vmi.pause_guard()?;

    let info = vmi.info()?;
    eprintln!(
        "VM info: {} vCPUs, page_size={}",
        info.vcpus, info.page_size
    );

    // Read a page of guest physical memory and hexdump it.
    let gfn = Gfn(0); // First page of physical memory
    match vmi.read_page(gfn) {
        Ok(page) => {
            let pa = Aarch64::pa_from_gfn(gfn);
            println!("=== Guest physical page at {pa} ===");
            for (i, chunk) in page.chunks(16).take(4).enumerate() {
                print!("  {:#010x}: ", pa.0 + (i * 16) as u64);
                for byte in chunk {
                    print!("{byte:02x} ");
                }
                println!();
            }
            println!("  ... ({} bytes total)", page.len());
        }
        Err(e) => eprintln!("Failed to read page at GFN {gfn}: {e}"),
    }

    Ok(())
}
```

- [ ] **Step 2: Add example entry to workspace Cargo.toml**

Add after the last `[[example]]` block:

```toml
[[example]]
name = "kvm-basic-aarch64"
path = "examples/kvm-basic-aarch64.rs"
required-features = ["arch-aarch64", "driver-kvm"]
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --example kvm-basic-aarch64`
Expected: PASS (on aarch64) or compile error about missing aarch64 arch adapter (on x86_64, which is expected since the driver's ArchAdapter impl is cfg-gated)

- [ ] **Step 4: Commit**

```bash
git add examples/kvm-basic-aarch64.rs Cargo.toml
git commit -m "feat: add kvm-basic-aarch64 example"
```

---

### Task 15: Final Verification

- [ ] **Step 1: Full workspace check**

Run: `cargo check --all-features`
Expected: PASS

- [ ] **Step 2: Verify docs build**

Run: `cargo doc --all-features --no-deps`
Expected: PASS (aarch64 docs generated)

- [ ] **Step 3: Run clippy**

Run: `cargo clippy --all-features`
Expected: No errors (warnings about unused code on non-aarch64 are acceptable)

- [ ] **Step 4: Final commit if any fixups needed**

```bash
git commit -m "chore: fix clippy warnings for aarch64 support"
```
