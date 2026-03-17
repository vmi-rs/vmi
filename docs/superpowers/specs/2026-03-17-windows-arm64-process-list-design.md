# Windows ARM64 Process List — Design Spec

**Goal:** Add Windows OS support for AArch64 architecture, enabling a `kvm-basic-process-list-aarch64` example that lists processes in a Windows 11 ARM64 KVM guest.

**Prerequisite:** The `vmi-arch-aarch64` crate and KVM driver adapter (already implemented).

---

## Components

### 1. `vmi-os-windows/src/arch/aarch64.rs` — ArchAdapter for Aarch64

New file implementing the `ArchAdapter<Driver>` trait for `Aarch64`. Methods:

- **`find_kernel`**: Read `registers.vbar_el1`, align to page boundary via `Aarch64::PAGE_MASK`, scan backward up to 32 MB in `PAGE_SIZE` steps looking for MZ header. Validate with CodeView debug information. Same algorithm as AMD64's `find_kernel` but anchored from VBAR_EL1 instead of MSR_LSTAR. Uses a generic version of `image_codeview` (see Section 9).

- **`kernel_image_base`**: Compute `vbar_el1 - KiArm64ExceptionVectors` symbol offset. Cache result in `OnceCell<Va>` (same pattern as AMD64). Uses the new optional `KiArm64ExceptionVectors` symbol (see Section 5).

- **`current_kpcr`**: Return `Va(registers.tpidr_el1)`. If `tpidr_el1 == 0`, this will produce an invalid address — callers should handle gracefully.

- **`syscall_argument`**: AAPCS64 calling convention. Arguments 0-7 from `registers.x[0]` through `registers.x[7]`. Arguments 8+ read from stack at `registers.sp + (index - 8) * 8`.

- **`function_argument`**: Same as `syscall_argument` (ARM64 uses the same register convention for both).

- **`function_return_value`**: Return `registers.x[0]`.

- **`is_page_present_or_transition`**: Stub returning `Ok(true)`. Add `// TODO: implement Windows ARM64 transition PTE check` comment.

#### Windows-specific extension traits

The AMD64 module defines and re-exports `WindowsPageTableEntry`, `WindowsExceptionVector`, and `WindowsInterrupt` extension traits. The AArch64 module needs equivalents:

- **`WindowsPageTableEntry` for `aarch64::PageTableEntry`**: Implement `windows_prototype` and `windows_transition` as stubs returning `false` (until Windows ARM64 PTE encoding is known).

- **`WindowsExceptionVector`**: Not applicable to ARM64 interrupt model. The re-export from `arch/mod.rs` and `lib.rs` will be cfg-gated behind `feature = "arch-amd64"`, so no AArch64 equivalent is needed.

- **`WindowsInterrupt`**: Same — cfg-gated behind `feature = "arch-amd64"`.

### 2. `translation_root_from_raw` — ArchAdapter trait addition

Add to `vmi-os-windows/src/arch/mod.rs`:

```rust
fn translation_root_from_raw(value: u64) -> Pa;
```

**AMD64 impl:** `Pa::from(Cr3(value))` — preserves existing Cr3 masking semantics.

**AArch64 impl:** `ttbr_to_pa(value)` — masks ASID bits [63:48] and CnP bit [0].

### 3. `process.rs` — Remove Cr3 dependency

In `crates/vmi-os-windows/src/comps/object/process.rs`:

- Remove `use vmi_arch_amd64::Cr3;` import.
- Replace `translation_root()` body: read raw u64, call `Driver::Architecture::translation_root_from_raw(raw)`.
- Same for `user_translation_root()`.
- Fix `architecture()` method: currently returns hardcoded `Amd64` for native processes. Add `fn native_image_architecture() -> VmiOsImageArchitecture` as an associated function on `ArchAdapter` (no `self`/`vmi` needed). AMD64 returns `Amd64`, AArch64 returns `Aarch64`. For WoW64 on ARM64, return `X86` (Windows ARM64 emulates x86 for most WoW64 apps — same as current behavior).

### 4. `vmi-os-windows/src/arch/mod.rs` — Module wiring

Use **feature flags** (not `target_arch` cfg gates) since VMI introspects guests that may differ from the host architecture:

- Gate `mod amd64;` with `#[cfg(feature = "arch-amd64")]`
- Add `#[cfg(feature = "arch-aarch64")] mod aarch64;`
- Gate the `pub use` re-exports per feature flag
- The re-export of `WindowsExceptionVector`, `WindowsInterrupt`, `WindowsPageTableEntry` from `arch/mod.rs` and `lib.rs` must be feature-gated to match

### 5. Symbols and Offsets — Make AMD64-only fields optional

**`crates/vmi-os-windows/src/offsets/mod.rs`:**

The `Symbols` struct has mandatory fields (`KiSystemCall32`, `KiSystemCall64`) that don't exist in ARM64 PDB profiles. These must become `Option<u64>`. Add new optional field:

```rust
KiArm64ExceptionVectors: Option<u64>,
```

The `_KTRAP_FRAME` in `OffsetsCommon` has AMD64-specific register fields (`Rax`, `Rcx`, `Rdx`, `R8`, `R9`, `R10`, `R11`, `Rip`, `Rsp`). These must become `Option<Field>` since ARM64 `_KTRAP_FRAME` has different field names. Affected call sites:

- `amd64.rs:184` — `symbols.KiSystemCall64` used in `kernel_image_base`. Must unwrap with `.ok_or(VmiError::NotSupported)?`.
- `comps/trap_frame.rs` — `instruction_pointer()` reads `KTRAP_FRAME.Rip`, `stack_pointer()` reads `KTRAP_FRAME.Rsp`. Both must return an error when the field is `None`. On ARM64 these would be `Pc` and `Sp` respectively — add those as additional `Option<Field>` entries, and have the accessors try the architecture-appropriate field first.

### 6. `VmiOsImageArchitecture` — Add Aarch64 variant

In `crates/vmi-core/src/os/image.rs`, add `Aarch64` variant to the enum.

In `crates/vmi-os-windows/src/comps/image.rs`, the `architecture()` method currently maps PE optional header types to X86/Amd64. Since ARM64 PE images also use `ImageOptionalHeader64`, additionally check the PE machine type field (`IMAGE_FILE_MACHINE_ARM64 = 0xAA64`) to distinguish ARM64 from AMD64.

### 7. `vmi-os-windows/Cargo.toml` — Dependencies

Use feature flags (matching the workspace pattern):

```toml
[features]
arch-amd64 = ["vmi-arch-amd64"]
arch-aarch64 = ["vmi-arch-aarch64"]

[dependencies]
vmi-arch-amd64 = { workspace = true, optional = true }
vmi-arch-aarch64 = { workspace = true, optional = true }
```

Update the workspace `Cargo.toml` feature propagation so that `arch-amd64` and `arch-aarch64` features on the root `vmi` crate propagate through `vmi-os-windows`.

### 8. Example — `kvm-basic-process-list-aarch64.rs`

Mirrors `kvm-basic-process-list.rs`:

- `find_qemu_vm(target_pid: Option<u32>)` helper (same pattern, with optional PID arg)
- Uses `VmiKvmDriver::<Aarch64>`
- `WindowsOs::find_kernel(&core, &registers)` to locate kernel
- Load ISR profile via `IsrCache`
- `WindowsOs::<VmiKvmDriver<Aarch64>>::new(&profile)`
- Create `VmiSession`, pause, list processes with `vmi.os().processes()`

### 9. `image_codeview` — Make generic

The `image_codeview` helper in `arch/amd64.rs` is hardcoded with `Driver: VmiRead<Architecture = Amd64>`. Extract into a shared function generic over `Architecture` (or move to a common module in `arch/`), so both AMD64 and AArch64 `find_kernel` can use it.

### 10. Workspace `Cargo.toml`

Add `[[example]]` entry:
```toml
[[example]]
name = "kvm-basic-process-list-aarch64"
path = "examples/kvm-basic-process-list-aarch64.rs"
required-features = ["arch-aarch64", "driver-kvm", "os-windows"]
```

Update `arch-amd64` and `arch-aarch64` feature definitions to propagate to `vmi-os-windows`:

```toml
arch-aarch64 = [
    "vmi-arch-aarch64",
    "vmi-os-windows?/arch-aarch64",
]
arch-amd64 = [
    "vmi-arch-amd64",
    "vmi-utils?/arch-amd64",
    "vmi-os-windows?/arch-amd64",
]
```

---

## Out of Scope

- Linux guest support (future work)
- Windows ARM64 transition PTE encoding (stubbed)
- 32-bit ARM (Aarch32) support
- Cross-architecture VMI (host ≠ guest arch) — feature flags enable it structurally, but testing is out of scope

## Risks

- **`vbar_el1` availability**: The register must be populated in `Registers`. Currently it's in the "extra registers" section (populated from `KVM_GET_ONE_REG`). If KVM doesn't provide it, `find_kernel` will fail. Mitigation: error message explaining the requirement.

- **`KiArm64ExceptionVectors` symbol**: The ISR profile for Windows ARM64 must contain this symbol for `kernel_image_base` to work. If the symbol name differs, it needs adjustment.

- **ISR profile availability**: The `IsrCache` must have Windows ARM64 PDB profiles. If CodeView info from the kernel PE is valid, `isr.entry_from_codeview()` should work regardless of architecture.

- **Optional symbols/offsets**: Making `KiSystemCall32`/`KiSystemCall64` and `_KTRAP_FRAME` fields optional touches existing AMD64 code paths. All call sites must be audited to handle `None` without regressing AMD64 behavior (these fields will still be `Some` on AMD64 profiles).

- **Serialization**: Adding `Aarch64` to `VmiOsImageArchitecture` (which derives `Serialize, Deserialize`) is a minor API change. Unlikely to break anything in practice.
