# Windows Bridge Example Plan

## Goal

Turn `bin/windows-bridge` into an educational, end-to-end example of using
`vmi-utils::bridge` with injected Windows shellcode. The first operation is
`pull`: download a file in the guest, optionally extract it, and optionally
execute a file from the downloaded or extracted content.

The implementation should explain the protocol through clear types and names,
not by preserving accidental structure from `_tmp` or `_scfw`.

## Working Agreement

- Work one milestone at a time and stop for review at each milestone boundary.
- Ask before making a protocol or user-interface choice that is not settled in
  this plan.
- Use `_tmp` and `_scfw` only as behavioral references.
- Write `bridge.h`, the pull shellcode, and the Rust host integration from
  first principles.
- Reuse the assembly instruction sequences where the ABI leaves no meaningful
  alternative, but rename and document them accurately.
- Keep the example focused. Do not bring over unrelated environment and file
  transfer bridges.
- Keep `_tmp` and `_scfw` as reference trees after the replacement reaches
  parity. They are not part of the active build.
- Preserve existing user changes. At discovery time, `bin/`, `.claude/`, and
  `.vscode/` are untracked, while `Cargo.toml` and `Cargo.lock` are modified.

## Important Integration Constraint

The current user-mode injector enables Xen hypercall monitoring only after its
injection recipe has completed. The recipe therefore cannot synchronously call
the pull shellcode and expect bridge requests to be handled.

The intended flow is:

1. Find a suitable target process.
2. Allocate executable guest memory with `VirtualAlloc`.
3. Copy a block containing the shellcode and its parameters into that memory.
4. Launch the shellcode with `CreateThread`.
5. Let the recipe finish so the injector enters bridge mode.
6. Let the shellcode's initial bridge gate retry until the host handler is
   ready.
7. Handle pull stage requests until the shellcode reports a terminal status.
8. Let SCFW self-cleanup release the allocation when the shellcode returns.

The allocation must begin with the SCFW blob because SCFW cleanup passes its
own base address to `VirtualFree(..., MEM_RELEASE)`.

## Current Repository State

- `bin/windows-bridge/Cargo.toml` already defines the workspace binary and its
  VMI dependencies.
- `bin/windows-bridge/src/main.rs` creates a Windows/Xen VMI session but does
  not yet select a process or run an injector.
- `bin/windows-bridge/src/_tmp` contains stale host bridge sketches that refer
  to old project types. Their request flow is useful, but the code is not
  directly reusable.
- `bin/windows-bridge/_scfw` contains a prototype build, bridge transport,
  several unrelated shellcodes, a mostly empty `pull`, and a large `download`
  prototype.
- The adjacent framework is at `../scfw` from the VMI repository root.
- `vmi-utils::bridge` supports VMCALL and CPUID packet decoding on AMD64, but
  the current user injector monitors only Xen hypercall events.
- `vmi-utils::injector` supports Windows AMD64 and 64-bit process injection.
  Its current documentation says 32-bit process injection is unsupported.

## Provisional Design

These choices are recommendations until explicitly accepted.

### SCFW layout

```text
bin/windows-bridge/scfw/
  .gitignore
  CMakeLists.txt
  CMakePresets.json
  bridge/
    CMakeLists.txt
    include/bridge.h
    src/arch/x64/transport.S
  shellcodes/
    CMakeLists.txt
    pull/
      CMakeLists.txt
      main.cpp
```

Use `transport.S` instead of `intrin.S`: the file implements two packet
transports, not compiler intrinsics. Its x64 implementation exposes both CPUID
and Xen VMCALL entry points, while the pull shellcode explicitly selects Xen
VMCALL. The example does not claim x86 runtime or build support because the
current Rust injector cannot inject 32-bit processes.

### Guest parameter block

Prefer a versioned fixed header followed by UTF-16LE, NUL-terminated strings.
Header fields contain offsets relative to the start of the parameter block.
This is more explicit and safely validated than an order-dependent cursor of
optional strings.

Candidate fields:

- total byte size and protocol version
- operation flags
- URL offset
- download path offset
- optional extraction directory offset
- optional executable path offset
- optional command-line offset
- optional working-directory offset
- window display value

Zero offsets represent absent optional strings. The final layout and integer
types must be agreed before implementation because Rust and C++ share this ABI.

### Bridge protocol

Use one request code for pull and methods for stage gates and terminal status.
The host response to a stage gate is one of `continue`, `wait`, or `abort`.
Responses carry verification values so the shellcode can distinguish an
unhandled hypercall from a valid host response.

Candidate methods:

- ready/download gate, including retry number after a failed download
- extraction gate
- execution gate
- terminal exit with status and optional native error details

Keep protocol constants mirrored and visibly grouped in C++ and Rust. Avoid a
macro that hides the Rust `BridgeContract` implementation in this example.
Use new example-specific magic and verification values with readable byte-string
derivations. The scratch constants are not a compatibility requirement.

### Shellcode delivery

Prefer loading `pull.bin` from a documented runtime path rather than using
`include_bytes!`. Runtime loading keeps `cargo check` independent of the CMake
toolchain and makes the two build steps visible to readers of the example.

## Milestones

### M0: Discovery and decisions

Status: complete

Deliverables:

- Map the current bridge, injector, SCFW, scratch, and workspace APIs.
- Record the monitor lifecycle constraint and proposed launch flow.
- Identify the decisions that gate each milestone and settle those needed by
  the transport scaffold.

Decisions made:

- Runtime and SCFW build scope: x64 only.
- Assembly exports: CPUID and Xen VMCALL.
- Pull transport: Xen VMCALL, selected explicitly in C++.
- Protocol identity: new readable constants.
- Prototype cleanup: keep `_tmp` and `_scfw` as inactive references.

Acceptance:

- No unresolved choice affects the M1 file layout or transport API.

### M1: SCFW and bridge transport scaffold

Status: complete

Deliverables:

- Create the new `scfw` tree without copying unrelated prototype targets.
- Add x64 presets and adjacent-SCFW integration.
- Add `transport.S` for x64 with CPUID and Xen VMCALL entry points.
- Write a small, type-safe `bridge.h` from scratch.
- Leave `shellcodes/CMakeLists.txt` ready for the separately reviewed pull
  milestone.

Verification:

- Configure and build x64 Release.
- Syntax-check `bridge.h` with the SCFW Windows SDK include paths.
- Inspect the static archive's exported transport symbols.

Review boundary:

- Review names, packet layouts, ABI comments, and response verification before
  implementing pull behavior.

### M2: Pull shellcode

Status: in progress

Deliverables:

- Define and validate the parameter header and flags.
- Implement the startup/download gate and bounded host-controlled retry flow.
- Download with `URLDownloadToFileW`.
- Optionally create the destination directory and extract a ZIP archive.
- Optionally execute the selected file with arguments, working directory, and
  display policy.
- Report terminal status and useful Windows/HRESULT details to the host.
- Keep imports and SCFW options limited to what the implementation needs.

Implementation checkpoints:

1. Parameter parsing and a no-op successful terminal exchange.
2. Download only.
3. Optional extraction.
4. Optional execution.

Verification:

- Build x64 after every checkpoint.
- Check release shellcode size and section extraction.

Review boundary:

- Review shellcode behavior and error model before writing its host handler.

### M3: Rust pull bridge and injection recipe

Status: pending

Deliverables:

- Add a concrete Rust `BridgeContract` and `BridgeHandler` for pull.
- Model host policies such as retry limit and permission to extract or execute.
- Serialize the agreed parameter block with checked sizes and UTF-16 strings.
- Load the shellcode artifact.
- Build a page-aligned shellcode/parameter allocation.
- Add the `VirtualAlloc`, guest write, and `CreateThread` recipe.
- Complete the injector when the shellcode sends its terminal method.

Verification:

- Add focused unit tests for parameter serialization and policy transitions
  where the current API permits tests without a live VMI context.
- Run `cargo +nightly fmt -- --check`.
- Run `cargo check -p windows-bridge`.
- Run `cargo clippy -p windows-bridge` after the structure stabilizes.

Review boundary:

- Review the host/guest protocol correspondence and allocation lifetime.

### M4: Main binary and usage

Status: pending

Deliverables:

- Parse the selected user-facing inputs.
- Create the VMI session.
- Find and log the target process.
- Construct the pull request and host policy.
- Run `InjectorHandler::with_bridge(...).with_pid(...)`.
- Report success, guest failure, and malformed bridge packets distinctly.
- Document SCFW build and Rust invocation commands near the example.

Verification:

- Exercise help and invalid-input paths without a VM.
- Run Rust formatting, check, and clippy.

Review boundary:

- Review example readability and defaults before live testing.

### M5: End-to-end validation and polish

Status: pending

Scenarios:

- Download only.
- Download with a forced retry and host retry limit.
- Download and extract a ZIP.
- Download and execute directly.
- Download, extract, and execute with optional arguments and working directory.
- Host abort at each stage.
- Guest API failure with useful terminal diagnostics.

Acceptance:

- The injected thread terminates and SCFW frees its allocation.
- The injector receives one terminal result and disables monitoring cleanly.
- No active build or Rust module refers to a prototype-only path or stale type.
- Build and run instructions can be followed from a clean checkout with the
  adjacent `scfw` repository available.

## Open Decisions

1. Is `bin/windows-bridge` the final package name?
2. Should extraction support ZIP only through `Shell.Application`, matching
   the prototype's broad approach?
3. Should the fixed-header parameter ABI replace the prototype's sequential
   cursor format?
4. Should the CLI use a dedicated parser dependency or a small manual parser?
5. Should `pull.bin` be loaded at runtime from a path, embedded at compile time,
   or built through `build.rs`?
6. Should execute and extract permission be controlled only by requested
   operation flags, or independently approved by host-side policy?

## Resume Checkpoint

Current milestone: M2, checkpoint 1.

Next action: agree on the parameter ABI and bridge methods, then create the pull
target with parameter parsing and a terminal bridge exchange only.
