# AArch64 Architecture Support — Design Spec

## Overview

Add AArch64 (ARM64) architecture support to vmi-rs, enabling VMI on arm64 KVM guests. Scope covers a new `vmi-arch-aarch64` crate implementing the `Architecture` trait, and an arm64 `ArchAdapter` in `vmi-driver-kvm`. OS-level adapters (vmi-os-linux, vmi-os-windows) are out of scope.

## Deliverables

1. **`vmi-arch-aarch64` crate** — architecture types, paging, events, interrupts
2. **`vmi-driver-kvm` aarch64 adapter** — ring event conversion, event monitoring, interrupt injection
3. **Workspace integration** — Cargo.toml updates, feature flags
4. **Example** — `kvm-basic-aarch64` demonstrating VMI session setup and memory read on arm64

## 1. `vmi-arch-aarch64` Crate

New workspace member at `crates/vmi-arch-aarch64/`. Follows the structure of `vmi-arch-amd64`.

### 1.1 Module Layout

```
crates/vmi-arch-aarch64/
  Cargo.toml
  src/
    lib.rs          # Aarch64 struct, Architecture impl, trait impls, re-exports
    registers.rs    # Registers, GpRegisters, Pstate
    paging.rs       # PageTableLevel, PageTableEntry, descriptor parsing
    translation.rs  # Page table walk, VaTranslation, TranslationEntry
    event.rs        # EventMonitor, EventReason, event data structs
    interrupt.rs    # Interrupt, SyncException, injection types
    address.rs      # TTBR -> Pa/Gfn conversions, VA canonicalization
```

### 1.2 `Aarch64` Struct and `Architecture` Impl

```rust
pub struct Aarch64;

impl Architecture for Aarch64 {
    const PAGE_SIZE: u64 = 0x1000;       // 4KB
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xFFFF_FFFF_FFFF_F000;

    // BRK #0 = 0xD4200000. AArch64 instructions are fixed-width 4 bytes.
    // Software breakpoint insertion must target 4-byte-aligned addresses
    // and save/restore all 4 bytes of the original instruction.
    const BREAKPOINT: &'static [u8] = &[0x00, 0x00, 0x20, 0xD4]; // BRK #0 (LE)

    type Registers = Registers;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = SystemRegister;
    type EventMonitor = EventMonitor;
    type EventReason = EventReason;
}
```

**`Architecture` trait methods** — all address conversion methods use the same index/offset/mask values as amd64 4-level paging since 4KB-granule arm64 has identical bit layout:

| Method | Implementation |
|--------|---------------|
| `gfn_from_pa(pa)` | `pa.0 >> 12` |
| `pa_from_gfn(gfn)` | `gfn.0 << 12` |
| `pa_offset(pa)` | `pa.0 & 0xFFF` |
| `va_index_for(va, L0)` | `(va.0 >> 39) & 0x1FF` |
| `va_index_for(va, L1)` | `(va.0 >> 30) & 0x1FF` |
| `va_index_for(va, L2)` | `(va.0 >> 21) & 0x1FF` |
| `va_index_for(va, L3)` | `(va.0 >> 12) & 0x1FF` |
| `va_offset_for(va, L0)` | `va.0 & 0x7F_FFFF_FFFF` |
| `va_offset_for(va, L1)` | `va.0 & 0x3FFF_FFFF` |
| `va_offset_for(va, L2)` | `va.0 & 0x1F_FFFF` |
| `va_offset_for(va, L3)` | `va.0 & 0xFFF` |
| `va_align_down(va)` | `va & PAGE_MASK` |
| `va_align_up(va)` | `(va + 0xFFF) & PAGE_MASK` |

### 1.3 Registers

**`Pstate`** — newtype wrapper around `u64`, deriving `Debug, Default, Clone, Copy, PartialEq, Eq`. Accessor methods for condition flags (N, Z, C, V), exception masking bits (DAIF), execution state (nRW, EL, SP), and IL/SS.

**`Registers`** — full CPU state snapshot:

```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct Registers {
    // General-purpose registers
    pub x: [u64; 31],       // x0-x30
    pub sp: u64,             // SP_EL1
    pub pc: u64,             // ELR_EL2 (program counter)
    pub pstate: Pstate,      // SPSR_EL2

    // System registers (from ring event — read-only in ring, writable via ioctls)
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub mair_el1: u64,
    pub contextidr_el1: u64,

    // Extra registers (populated from KVM_GET_ONE_REG when available, zero otherwise)
    pub vbar_el1: u64,
    pub tpidr_el1: u64,
    pub sp_el0: u64,
}
```

**`GpRegisters`** — subset for event response SET_REGS:

```rust
#[derive(Debug, Default, Clone, Copy)]
pub struct GpRegisters {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: Pstate,
}
```

**`Registers` trait impl**:

| Method | Implementation |
|--------|---------------|
| `instruction_pointer()` | `self.pc` |
| `set_instruction_pointer(ip)` | `self.pc = ip` |
| `stack_pointer()` | `self.sp` |
| `set_stack_pointer(sp)` | `self.sp = sp` |
| `result()` | `self.x[0]` (x0 is the return value register) |
| `set_result(v)` | `self.x[0] = v` |
| `gp_registers()` | Copy x, sp, pc, pstate into `GpRegisters` |
| `set_gp_registers(gp)` | Copy from `GpRegisters` into self |
| `address_width()` | `8` (64-bit pointers) |
| `effective_address_width()` | `8` |
| `translation_root(va)` | TTBR selection based on VA bit 55 (see below) |
| `access_context(va)` | `AccessContext::from(self.address_context(va))` |
| `address_context(va)` | `AddressContext::from((va, self.translation_root(va)))` |
| `return_address(vmi)` | `Ok(Va(self.x[30]))` — arm64 LR is x30 (known limitation: non-leaf functions may have saved LR to stack) |

**TTBR selection for `translation_root(va)` and `access_context(va)`**: On arm64, the virtual address space is split: bit 55 selects which TTBR to use. `if va.0 & (1 << 55) != 0 { ttbr1_el1 } else { ttbr0_el1 }`. This differs from amd64 where CR3 is used for all VAs.

### 1.4 Paging (4KB Granule Only)

**`PageTableLevel`**:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableLevel {
    L0,   // PGD — VA[47:39], 512GB region
    L1,   // PUD — VA[38:30], 1GB blocks possible
    L2,   // PMD — VA[29:21], 2MB blocks possible
    L3,   // PTE — VA[20:12], 4KB pages
}
```

**`PageTableEntry`** — `#[repr(transparent)]` newtype around `u64` (deriving `FromBytes` from zerocopy) with methods:
- `valid() -> bool` — bit 0
- `is_table() -> bool` — bits [1:0] == 0b11 (valid + table bit), only meaningful at L0-L2
- `is_block() -> bool` — bits [1:0] == 0b01 (valid + block type), at L1/L2
- `is_page() -> bool` — bits [1:0] == 0b11, at L3 (same encoding as table but at leaf level)
- `output_address() -> Pa` — bits [47:12] masked (standard 48-bit OA)
- `pfn() -> Gfn` — `output_address() >> PAGE_SHIFT`
- `af() -> bool` — bit 10 (access flag)
- `ap() -> u8` — bits [7:6] (access permission)
- `xn() -> bool` — bit 54 (execute-never for EL0, UXN)
- `pxn() -> bool` — bit 53 (privileged execute-never)

**`translate_address`** — 4-level walk (L0 → L1 → L2 → L3):
1. Select TTBR based on VA bit 55. Extract BADDR by masking with `0x0000_FFFF_FFFF_F000` (clears upper ASID bits [63:48] and CnP bit [0]).
2. Walk L0: index = VA[47:39], check valid. L0 cannot be a block descriptor with 4KB granule.
3. Walk L1: index = VA[38:30], check valid. If block → 1GB mapping, PA = `output_address | va_offset_for(va, L1)`.
4. Walk L2: index = VA[29:21], check valid. If block → 2MB mapping, PA = `output_address | va_offset_for(va, L2)`.
5. Walk L3: index = VA[20:12], check valid, check `is_page()` → 4KB page, PA = `output_address | va_offset_for(va, L3)`.

**`Aarch64::translation()`** — richer version returning `VaTranslation` with all intermediate `TranslationEntry` records (level, entry value, entry address), mirroring the amd64 `Amd64::translation()` method for debugging and introspection tools.

### 1.5 Events

**`EventMonitor`**:

```rust
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor BRK software breakpoints.
    /// (Unlike amd64's EventMonitor::Interrupt(ExceptionVector::Breakpoint),
    /// arm64 uses a flat variant since it doesn't have x86 exception vectors.)
    Breakpoint,
    /// Monitor system register writes (sctlr_el1, ttbr0/1_el1, tcr_el1).
    Sysreg(SystemRegister),
    /// Monitor single-step completion.
    Singlestep,
}
```

**`SystemRegister`** (the `SpecialRegister` associated type):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    SctlrEl1,
    Ttbr0El1,
    Ttbr1El1,
    TcrEl1,
}
```

**`EventReason`**:

```rust
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    MemoryAccess(EventMemoryAccess),
    Breakpoint(EventBreakpoint),
    Sysreg(EventSysreg),
    Singlestep(EventSinglestep),
}
```

**Event data structs**:

```rust
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess {
    pub pa: Pa,
    pub va: Va,
    pub access: MemoryAccess,
}

/// BRK software breakpoint event.
/// Implements `EventInterrupt` (via `fn gfn()`) so it can be returned
/// from `EventReason::as_interrupt()` and `as_software_breakpoint()`.
#[derive(Debug, Clone, Copy)]
pub struct EventBreakpoint {
    pub gfn: Gfn,        // Converted from kernel-provided gpa: gpa >> PAGE_SHIFT
    pub pc: Va,
    pub comment: u16,     // BRK #imm16
}

#[derive(Debug, Clone, Copy)]
pub struct EventSysreg {
    pub register: SystemRegister,
    pub old_value: u64,
    pub new_value: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep {
    pub gfn: Gfn,
}
```

**Trait impls on event types**:
- `EventMemoryAccess` implements `vmi_core::arch::EventMemoryAccess` — `pa()`, `va()`, `access()`
- `EventBreakpoint` implements `vmi_core::arch::EventInterrupt` — `fn gfn(&self) -> Gfn { self.gfn }`
- `EventReason` implements `vmi_core::arch::EventReason`:
  - `as_memory_access()` → `Some` for `MemoryAccess` variant
  - `as_interrupt()` → `Some(&self.breakpoint)` for `Breakpoint` variant (since `EventBreakpoint` implements `EventInterrupt`)
  - `as_software_breakpoint()` → `Some(&self.breakpoint)` for `Breakpoint` variant

### 1.6 Interrupts (Injection)

Higher-level types that encode into ESR values for `kvm_vmi_inject_event`.

```rust
#[derive(Debug, Clone, Copy)]
pub enum Interrupt {
    /// Synchronous exception — encoded as full ESR value.
    Sync(SyncException),
    /// Asynchronous SError — ISS portion only.
    SError { iss: u32 },
}

#[derive(Debug, Clone, Copy)]
pub enum SyncException {
    /// Data abort (EC=0x24/0x25). Fields: ISS, IL (instruction length).
    DataAbort { iss: u32, il: bool },
    /// Instruction abort (EC=0x20/0x21).
    InstructionAbort { iss: u32, il: bool },
    /// BRK instruction (EC=0x3C).
    Brk { comment: u16 },
    /// SVC instruction (EC=0x15).
    Svc { imm16: u16 },
    /// HVC instruction (EC=0x16).
    Hvc { imm16: u16 },
    /// Raw ESR value for other exception classes.
    Raw { esr: u64 },
}
```

**ESR encoding** (`SyncException::to_esr() -> u64`):
- `DataAbort { iss, il: true }` → `(0x25 << 26) | (1 << 25) | iss`
- `DataAbort { iss, il: false }` → `(0x24 << 26) | iss`
- `InstructionAbort { iss, il: true }` → `(0x21 << 26) | (1 << 25) | iss`
- `InstructionAbort { iss, il: false }` → `(0x20 << 26) | iss`
- `Brk { comment }` → `(0x3C << 26) | (1 << 25) | comment as u64`
- `Svc { imm16 }` → `(0x15 << 26) | (1 << 25) | imm16 as u64`
- `Hvc { imm16 }` → `(0x16 << 26) | (1 << 25) | imm16 as u64`
- `Raw { esr }` → `esr`

The `Interrupt` type determines the KVM injection type: `Sync` → `KVM_VMI_ARM64_INJECT_SYNC`, `SError` → `KVM_VMI_ARM64_INJECT_SERROR`.

### 1.7 `address.rs` Module

Conversions from TTBR values to `Pa` and `Gfn`:

```rust
/// Extract the base address from a TTBR value.
/// Masks out ASID bits [63:48] and CnP bit [0].
pub fn ttbr_to_pa(ttbr: u64) -> Pa {
    Pa(ttbr & 0x0000_FFFF_FFFF_F000)
}

pub fn ttbr_to_gfn(ttbr: u64) -> Gfn {
    Gfn::new((ttbr & 0x0000_FFFF_FFFF_F000) >> 12)
}
```

### 1.8 Dependencies

```toml
[dependencies]
bitflags = { workspace = true }
zerocopy = { workspace = true, features = ["derive"] }
vmi-core = { workspace = true }
```

## 2. `vmi-driver-kvm` AArch64 Adapter

### 2.1 Module Layout

```
crates/vmi-driver-kvm/src/arch/
  mod.rs              # ArchAdapter trait + cfg-gated module includes
  amd64/              # existing (cfg(target_arch = "x86_64"))
  aarch64/            # new (cfg(target_arch = "aarch64"))
    mod.rs            # ArchAdapter impl for Aarch64
    registers.rs      # kvm_vmi_regs <-> Registers conversion
    event.rs          # KvmVmiEventReason -> EventReason mapping
```

The `convert` module (`FromExt`, `IntoExt`, `TryFromExt`) is currently gated behind `cfg(target_arch = "x86_64")`. The aarch64 adapter will also need it — remove the cfg gate so both arches can use it.

### 2.2 Register Conversion

**Ring event → Registers** (`registers_from_ring`):
- Map `kvm_vmi_regs.regs[0..31]` → `Registers.x[0..31]`
- Map `sp`, `pc`, `pstate` directly
- Map system registers (`sctlr_el1`, `ttbr0_el1`, etc.) directly
- Extra registers (`vbar_el1`, `tpidr_el1`, `sp_el0`) set to 0 (not in ring event)

**Registers → Ring event** (`registers_to_ring`):
- Reverse mapping. Only GP registers + pstate are meaningful (system registers are read-only in ring response).

**`registers_from_vcpu`**: Return `Err(Error::NotSupported)` — on arm64, registers come from ring events, not vCPU fd ioctls.

### 2.3 Event Mapping

**`KvmVmiEventReason` → `EventReason`**:

| KVM Event | VMI EventReason | Notes |
|-----------|----------------|-------|
| `MemoryAccess { gpa, access }` | `EventReason::MemoryAccess(...)` | `pa = Pa(gpa)`, `va = Va(0)` |
| `Breakpoint { pc, gpa, comment }` | `EventReason::Breakpoint(...)` | `gfn = Gfn(gpa >> PAGE_SHIFT)` |
| `Sysreg { reg, old_value, new_value }` | `EventReason::Sysreg(...)` | Map `reg` via `KVM_VMI_ARM64_SYSREG_*` |
| `Singlestep { gpa }` | `EventReason::Singlestep(...)` | `gfn = Gfn(gpa >> PAGE_SHIFT)` |

### 2.4 Monitor Enable/Disable

| EventMonitor | KVM Event ID |
|-------------|-------------|
| `Breakpoint` | `KVM_VMI_EVENT_BREAKPOINT_EVAL` |
| `Sysreg(_)` | `KVM_VMI_EVENT_SYSREG_EVAL` |
| `Singlestep` | `KVM_VMI_EVENT_SINGLESTEP` |

For `Sysreg`, arm64 sysreg monitoring is controlled by HCR_EL2.TVM which traps all system register writes at once — the param union is unused. The specific register is reported in the event, not filtered at enable time.

### 2.5 `process_event` Implementation

The `process_event` method is the core event dispatch. It follows the same structure as the amd64 version:

```rust
fn process_event(
    _driver: &KvmDriver<Self>,
    raw_event: &mut kvm::sys::kvm_vmi_ring_event,
    mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
) -> Result<(), Error> {
    // 1. Parse raw ring event into safe KvmVmiEvent
    let kvm_event = unsafe { kvm::KvmVmiEvent::from_raw(raw_event) }
        .ok_or(Error::NotSupported)?;

    // 2. Convert KvmVmiEventReason -> EventReason
    let vmi_reason = EventReason::try_from_ext(&kvm_event.reason)
        .map_err(|()| Error::NotSupported)?;

    // 3. Convert ring registers -> arch Registers
    let mut registers = Self::registers_from_ring(&raw_event.regs);

    // 4. Build VmiEvent, call handler
    let view = Some(View(kvm_event.view_id as u16));
    let flags = VmiEventFlags::VCPU_PAUSED;
    let vcpu_id = VcpuId::from(kvm_event.vcpu_id as u16);
    let vmi_event = VmiEvent::new(vcpu_id, flags, view, registers, vmi_reason);
    let vmi_response = handler(&vmi_event);

    // 5. Build ring response flags
    let mut response_flags: u32 = kvm::sys::KVM_VMI_RESPONSE_CONTINUE;

    // SET_REGS: write modified registers back
    if let Some(new_gp_regs) = &vmi_response.registers {
        registers.set_gp_registers(new_gp_regs);
        raw_event.regs = Self::registers_to_ring(&registers);
        response_flags |= kvm::sys::KVM_VMI_RESPONSE_SET_REGS;
    }

    // SWITCH_VIEW
    if let Some(new_view) = vmi_response.view {
        raw_event.view_id = new_view.0 as u32;
        response_flags |= kvm::sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
    }

    // Map VmiEventAction to KVM response flags
    match vmi_response.action {
        VmiEventAction::Continue => {}
        VmiEventAction::Deny => {
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_DENY;
        }
        VmiEventAction::ReinjectInterrupt => {
            // REINJECT is supported on arm64 — re-delivers the trapped
            // event (e.g., BRK) to the guest instead of suppressing it.
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
```

### 2.6 Interrupt Injection

```rust
fn inject_interrupt(
    driver: &KvmDriver<Self>,
    vcpu: VcpuId,
    interrupt: Interrupt,
) -> Result<(), Error> {
    let (typ, esr) = match interrupt {
        Interrupt::Sync(exc) => (kvm::sys::KVM_VMI_ARM64_INJECT_SYNC, exc.to_esr()),
        Interrupt::SError { iss } => (kvm::sys::KVM_VMI_ARM64_INJECT_SERROR, iss as u64),
    };
    driver.session.inject_event(
        u16::from(vcpu) as u32,
        typ,
        esr,
    )?;
    Ok(())
}
```

### 2.7 `reset_state`

```rust
fn reset_state(driver: &KvmDriver<Self>) -> Result<(), Error> {
    let _ = driver.monitor_disable(EventMonitor::Breakpoint);
    let _ = driver.monitor_disable(EventMonitor::Sysreg(SystemRegister::SctlrEl1));
    let _ = driver.monitor_disable(EventMonitor::Singlestep);
    // Disable mem_access events
    let _ = driver.monitor.control_event(&make_ctrl(
        kvm::sys::KVM_VMI_EVENT_MEM_ACCESS, 0,
    ));
    // Switch all vCPUs back to view 0
    let _ = driver.session.switch_view(0);
    // Destroy all views
    driver.views.borrow_mut().clear();
    Ok(())
}
```

### 2.8 Cargo.toml Change

```toml
[target.'cfg(target_arch = "aarch64")'.dependencies]
vmi-arch-aarch64 = { workspace = true }
```

## 3. Workspace Integration

### 3.1 `vmi/Cargo.toml`

Add to `[workspace.dependencies]`:
```toml
vmi-arch-aarch64 = { path = "./crates/vmi-arch-aarch64", version = "0.4.0" }
```

Add optional dependency and feature:
```toml
vmi-arch-aarch64 = { workspace = true, optional = true }

[features]
arch-aarch64 = ["vmi-arch-aarch64"]
```

Add `arch-aarch64` to `default` features (alongside `arch-amd64`).

### 3.2 `vmi/src/lib.rs`

Add `#[cfg(feature = "arch-aarch64")]` module re-export for the aarch64 architecture, mirroring the amd64 pattern.

## 4. Example: `kvm-basic-aarch64`

Minimal example (`examples/kvm-basic-aarch64.rs`) that:
1. Finds a QEMU process and duplicates its KVM fds (reuses the existing `find_qemu_vm` pattern)
2. Creates `VmiKvmDriver::<Aarch64>`
3. Pauses the VM
4. Reads a page of guest physical memory and hexdumps it
5. Prints basic VM info (page size, vCPU count)

This validates the full stack without requiring OS-level introspection.

## Out of Scope

- `vmi-os-linux` aarch64 adapter (kernel finding, process enumeration)
- `vmi-os-windows` aarch64 adapter
- 16KB and 64KB granule support
- 52-bit VA (LVA) / 52-bit PA (LPA) extensions
- SVE/SME register state
- Nested virtualization support
