# Windows Bridge Example Handoff

## Purpose

This document hands off the in-progress `bin/windows-bridge` example to a new
session. Read it before editing code. It records the agreed direction, completed
work, important implementation constraints, pending design decisions, and the
next concrete steps.

The user explicitly wants this work completed incrementally. Do not implement
the remaining project in one pass. Work through one checkpoint at a time, ask
questions where behavior is not settled, verify each checkpoint, and stop for
review at milestone boundaries.

## First Steps In A New Session

1. Load every file under `.claude/rules/`.
2. Read this file.
3. Read `.claude/plans/2026-07-15-windows-bridge-example.md` for the original
   roadmap. Where that plan still proposes a fixed-header parameter ABI, this
   handoff supersedes it: the user subsequently selected a sequential cursor.
4. Read the active M1 files under `bin/windows-bridge/scfw/`.
5. Inspect `git status` before editing. The workspace contains user changes and
   untracked files. Do not revert or overwrite them.

## Repository Rules That Matter

- Use ASCII and US English in code, comments, and documentation.
- Format Rust with `cargo +nightly fmt`, never stable rustfmt.
- `anyhow` belongs only at the `main` boundary. Other Rust modules should use
  concrete error types.
- Follow the Rust matching, naming, imports, and documentation rules in
  `.claude/rules/rust_style.md`.
- Working plans belong under `.claude/plans/`.
- Never add a `Co-Authored-By` trailer.
- Preserve unrelated worktree changes.

## Goal

Turn `bin/windows-bridge` into an educational, end-to-end example of using the
guest-host `Bridge` from `vmi-utils`.

The example will:

1. Inject an SCFW user-mode shellcode into a Windows guest process.
2. Launch the shellcode in a new guest thread.
3. Communicate with that shellcode through Xen VMCALL bridge packets.
4. Download a file with `URLDownloadToFileW`.
5. Optionally extract a ZIP file through `Shell.Application`.
6. Optionally execute a selected file.
7. Report progress, policy gates, and a terminal result to the Rust host.

The active implementation should be written from first principles. The
prototype trees are behavioral references, not sources to copy wholesale.

## Reference Trees

Keep these trees in place as inactive references:

- `bin/windows-bridge/_scfw`
- `bin/windows-bridge/src/_tmp`

The user chose to retain them after the replacement reaches parity. Do not add
them to the active build or module tree.

Useful prototype files:

- `_scfw/bridge/include/bridge.h`
- `_scfw/bridge/src/arch/x64/intrin.S`
- `_scfw/shellcodes/download/main.cpp`
- `_scfw/shellcodes/pull/main.cpp`
- `src/_tmp/bridge.rs`
- `src/_tmp/bridge/download.rs`
- `src/_tmp/bridge/execute.rs`

The `_tmp` Rust code refers to stale types such as `deto_types`; use it only to
understand old behavior.

The adjacent SCFW repository is located at:

```text
/opt/dev/vmi-rs/scfw
```

From `bin/windows-bridge/scfw`, its relative path is `../../../../scfw`.

## Worktree State

At the last check, `git status --short` reported:

```text
 M Cargo.lock
 M Cargo.toml
?? .claude/
?? .vscode/
?? bin/
```

These changes predate or include this task. No commit has been created. The root
workspace `Cargo.toml` was already modified to include `bin/*`, and the lockfile
already contains the `windows-bridge` package.

## Architecture And Lifecycle Findings

### Runtime architecture

The user selected x64-only scope for this example.

- The active SCFW project has only x64 presets and x64 assembly.
- The transport documentation still describes x86 register mappings because
  the bridge protocol itself explains all CPUID/VMCALL pairs.
- Do not add an x86 build preset or claim 32-bit process injection support.
- `vmi-utils::injector` currently supports Windows AMD64 and does not support
  injection into 32-bit processes.

### Transport selection

The active x64 assembly exports both transports:

- `bridge_cpuid`
- `bridge_xen_vmcall`

The pull shellcode must explicitly use `bridge_xen_vmcall`. The current
user-mode injector monitors Xen hypercall events, not CPUID events.

### Critical injector lifecycle constraint

The user-mode injector enables hypercall monitoring only after its injection
recipe has completed. Therefore, the recipe must not synchronously call the
pull shellcode.

The intended launch flow is:

1. Select a target process.
2. Call `VirtualAlloc` for one executable allocation.
3. Copy the shellcode and its parameter bytes into the allocation.
4. Call `CreateThread` with the allocation base as the start address and the
   parameter location as `lpParameter`.
5. Let the recipe complete.
6. The injector transitions into bridge mode and enables hypercall monitoring.
7. The shellcode retries its initial bridge gate until it receives a verified
   host response.
8. The shellcode performs the requested work and sends one terminal exit.

Launching a separate thread is important. If the recipe directly invokes the
shellcode, its first VMCALL occurs while bridge monitoring is still disabled.

### SCFW self-cleanup constraint

`SCFW_OPT_CLEANUP` is enabled. SCFW passes the shellcode base address to
`VirtualFree(..., MEM_RELEASE)` when the shellcode returns.

The guest allocation must therefore begin with the SCFW `.bin` blob. Parameters
may follow it in the same allocation, but the thread start address must be the
allocation base. Do not place a header before the shellcode.

## Completed Work

### M0: discovery and roadmap

Completed.

The codebase was inspected for:

- repository rules
- current `vmi-utils::bridge` APIs
- user-mode injector lifecycle
- recipe construction and Windows call setup
- SCFW build conventions and self-cleanup
- prototype host bridge behavior
- prototype download/extract/execute behavior

The working roadmap is:

```text
.claude/plans/2026-07-15-windows-bridge-example.md
```

### M1: SCFW and bridge transport scaffold

Completed and reviewed.

Active files created:

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
```

#### CMake behavior

- Supports x64 only.
- Requires Clang.
- Uses the adjacent SCFW repository.
- Disables SCFW examples and tools.
- Enables SCFW self-cleanup.
- Provides `x64` and `x64-debug` presets.
- Ignores `build-*` directories.

#### Assembly naming

The assembly file is named `transport.S`, not `intrin.S`, because it implements
packet transports rather than compiler intrinsics.

It places both routines in `.text$15`, between SCFW startup code and the SCFW
entry wrapper. It preserves the required Windows x64 nonvolatile registers and
maps packets according to the `vmi-utils` bridge register ABI.

#### Header style

The user edited `bridge/include/bridge.h` and `transport.S` to their preferred
style. Preserve that style in future C++ and assembly edits.

The current header provides:

- `bridge::packet`
- `bridge::response`
- `bridge::transport_fn_t`
- `bridge_cpuid`
- `bridge_xen_vmcall`
- `bridge::client<...>`
- `client::send(...)` with verification of response values 3 and 4

The packet and response comments contain a four-way register table:

- CPUID x64
- CPUID x86
- VMCALL x64
- VMCALL x86

The header currently does not contain compile-time size/offset assertions for
the C++ structs mirrored by hard-coded assembly offsets. This was raised during
review. The user only requested that the register table be corrected and then
said the result was to their liking. Do not reintroduce those assertions without
discussing it.

#### M1 verification performed

Configuration succeeded:

```bash
cmake --preset x64
```

Build succeeded:

```bash
cmake --build --preset x64
```

The archive exported both expected symbols:

```text
bridge_cpuid
bridge_xen_vmcall
```

The final header passed a standalone Clang syntax check with the SCFW Windows
SDK include paths. An explicit temporary instantiation of
`client<&bridge_xen_vmcall, ...>` also passed. The temporary test file was
removed.

### M2 checkpoint 1: pull protocol skeleton

Completed and reviewed.

Active additions:

```text
bin/windows-bridge/scfw/bridge/include/parameters.h
bin/windows-bridge/scfw/shellcodes/pull/
  CMakeLists.txt
  main.cpp
```

The checkpoint adds:

- the generic verified `bridge::client::exit(...)` helper
- the approved sequential parameter ABI and shared minimal parameter cursor
- pull bridge identity, method, response, terminal status, stage, and detail
  constants
- an unbounded startup gate that retries every 250 milliseconds until a
  verified host `continue` or `abort`
- one terminal success, invalid-parameter, or aborted exchange

The Release build succeeded. PE verification reported one `.text` section and
no imports or exports. After the shared cursor refactor, the extracted
`pull.bin` is 1,184 bytes, matching the `.text` raw size.

### M2 checkpoint 2: download

Completed and reviewed.

The checkpoint adds:

- environment expansion for the destination path
- recursive destination-parent creation with `SHCreateDirectoryExW`
- `URLDownloadToFileW` with one-based failed-attempt reporting
- 250-millisecond waits for absent, unverified, or explicit `wait` responses
- host-controlled retry or abort after every failed attempt
- terminal Win32 path errors or the final download HRESULT with a compact API
  detail value
- uniform default flags dynamically load, resolve, and unload the declared
  Kernel32, Shell32, and URLMon modules

The Release build succeeded. PE verification reported one `.text` section and
no imports or exports. The extracted `pull.bin` is 2,505 bytes, matching the
`.text` raw size.

### M2 checkpoint 3: ZIP extraction

Completed and reviewed.

The checkpoint adds:

- COM initialization and balanced `CoUninitialize` cleanup
- local minimal `ComPtr` ownership and `DEFINE_GUID` definitions for `CLSID_Shell`
  and `IID_IShellDispatch`
- `Shell.Application` archive and output `NameSpace` calls
- `Folder::CopyHere` with silent, no-confirmation, and no-error-UI flags
- 100-millisecond output item-count polling for up to 60 seconds
- compact extraction HRESULT and failing-operation reporting
- destination-directory expansion and recursive creation
- parent-directory creation without modifying the caller's path buffer

The selected completion policy succeeds when the output folder's top-level
item count reaches the archive's top-level item count. It is deliberately the
small item-count policy selected for this checkpoint; it does not prove that
recursive extraction has completed and can be satisfied by pre-existing output
items.

The Release build succeeded. PE verification reported one `.text` section and
no imports or exports. The extracted `pull.bin` is 4,503 bytes, matching the
`.text` raw size. No live Windows/Xen guest test has been performed.

### M2 checkpoint 4: execution

Completed and reviewed.

The checkpoint adds:

- host-gated execution through bridge method `0x0003`
- `ShellExecuteExW` resolved dynamically through Shell32
- independent argument, working-directory, and display-value presence flags
- an optional download stage and a successful no-operation request
- initialization-time executable and explicit working-directory expansion
- the expanded executable parent as the default working directory
- the requested `show_window` value, defaulting to `SW_SHOWNORMAL`, without
  requesting or waiting on a process handle
- compact execution failures without a `GetLastError` dependency

The Release build succeeded. PE verification reported one `.text` section and
no imports or exports. The extracted `pull.bin` is 4,866 bytes, matching the
`.text` raw size. No live Windows/Xen guest test has been performed.

## Current Milestone

M3 is implemented and verified without a live guest. Stop for review before
starting the M4 main binary and user-facing orchestration.

## Decisions Already Made For M2

### Parameter representation

The user selected a sequential cursor, not the previously recommended fixed
header with relative offsets. `bridge::parameters` is shared by future
shellcodes and directly returns signed and unsigned 8-, 16-, 32-, and 64-bit
integers, `char*` strings, and `wchar_t*` strings. It intentionally performs no
bounds checking and scans strings until their NUL terminator.

### Operation flags

Use six flags:

- extract: `1 << 0`
- execute: `1 << 1`
- download: `1 << 2`
- arguments: `1 << 8`
- working directory: `1 << 9`
- show window: `1 << 10`

The argument, working-directory, and show-window flags are invalid unless
execute is also set. Extraction is invalid unless download is also set.

### Extraction

Support ZIP extraction through the Windows `Shell.Application` COM APIs. Do not
use `tar.exe`, PowerShell, or another external process for extraction.

### Error reporting

Use one terminal exit request. Do not send a separate error request before
exit, and do not define separate terminal methods for each stage.

The terminal packet carries:

- `value1` bits 0..7: stage (`none = 0`, `parameters = 1`,
  `initialization = 2`, `download = 3`, `extract = 4`, `execute = 5`)
- `value1` bits 8..15: compact stage-specific error code
- `value1` bits 16..23: stable status (`success = 0`,
  `invalid_parameters = 0xfd`, `operation_failed = 0xfe`,
  `aborted = 0xff`)
- `value2`: native error or HRESULT, or zero when not applicable
- `value3` and `value4`: zero

### Generic bridge exit helper

The user requested a generic static `client::exit(...)` helper. It now
delegates to `send(0xffff, ...)`, accepts four protocol-neutral values, and
returns `std::optional<response>` so terminal exchanges retain the same host
verification behavior as other methods.

Do not add the prototype's generic `error(0xfffe, ...)` helper unless the user
asks for it. The user selected a single terminal exit protocol.

## Agreed Sequential Parameter ABI

The user approved this layout for M2:

```text
u32 flags
if flags.download:
    UTF-16LE NUL-terminated URL
    UTF-16LE NUL-terminated download path
if flags.extract:
    UTF-16LE NUL-terminated extraction directory
if flags.execute:
    UTF-16LE NUL-terminated executable path
    if flags.arguments:
        UTF-16LE NUL-terminated arguments, empty means no arguments
    if flags.working_directory:
        UTF-16LE NUL-terminated non-empty working directory
    if flags.show_window:
        i32 show_window
```

The shellcode trusts the host-produced block. It carries no total length, and
the cursor does not check bounds, alignment, trailing data, or missing string
terminators. When the show-window field is absent, execution uses
`SW_SHOWNORMAL`.

When no operation flags are set, the request consumes only `flags` and returns
success at the `none` stage. Execute-only requests consume no download or
extraction fields and run only the requested executable.

Download, extraction, executable, and explicit working-directory paths are
expanded by `__entry` only when their operation is selected, before `Entry`
runs the requested stages. If
the working-directory flag is absent, execution uses the expanded executable's
parent; if that path has no parent separator, Windows uses the current
directory.

An absent optional field consumes no bytes. A present empty arguments field
still occupies its UTF-16 NUL terminator and advances the cursor. A present
empty working-directory field is invalid.

## Agreed Bridge Protocol

These values are approved for the active C++ and future Rust implementations.

### Identity

```text
magic:   "VMIB"     -> 0x42494d56
request: pull       -> 0x0001
verify3: "VMI-RS3!" -> 0x213353522d494d56
verify4: "VMI-RS4!" -> 0x213453522d494d56
```

### Methods

```text
download = 0x0001
extract  = 0x0002
execute  = 0x0003
exit     = 0xffff
```

The proposed download method combines readiness and retry reporting:

- attempt `0` is the startup/readiness gate
- attempt `1..` reports the corresponding failed download attempt

This allows the shellcode to wait until the injector has entered bridge mode.

### Host responses

```text
continue = 0x00000000
wait     = 0x00000001
abort    = 0xffffffff
```

For stage gates, an absent or unverified response behaves like `wait`. The
shellcode sleeps for 250 milliseconds before retrying. The startup gate retries
without a shellcode-side attempt limit until it receives a verified `continue`
or `abort`; later host policy will own overall timeout and retry limits.

## M2 Implementation Sequence

Do not build all shellcode behavior in one edit.

### Checkpoint 1: protocol skeleton

1. Resolve `client::exit(...)` semantics.
2. Confirm the sequential parameter layout and exact constants.
3. Create `scfw/shellcodes/pull/CMakeLists.txt`.
4. Add `add_subdirectory(pull)` to `scfw/shellcodes/CMakeLists.txt`.
5. Create `scfw/shellcodes/pull/main.cpp`.
6. Implement only:
   - SCFW configuration and imports needed for the bridge wait loop
   - pull bridge constants and type alias
   - cursor parsing and validation
   - startup bridge gate
   - terminal success/failure exit
7. Build and inspect `pull.bin`.
8. Stop for review.

### Checkpoint 2: download

1. Add `URLDownloadToFileW` and only the imports it requires.
2. Create the parent destination directory.
3. Implement the host-controlled retry loop.
4. Report the final HRESULT on failure.

For a failed download, the retry gate sends the one-based attempt in `value1`
and the zero-extended HRESULT in `value2`. A host `abort` after a failed
attempt produces terminal `operation_failed` with the final HRESULT; terminal
`aborted` is reserved for an abort at the initial readiness gate.
5. Build, inspect shellcode size, and stop for review.

### Checkpoint 3: ZIP extraction

1. Add COM initialization and `Shell.Application` creation.
2. Open the archive and output folder namespaces.
3. Call `Folder::CopyHere` without UI.
4. Handle its asynchronous completion carefully.
5. Ensure COM and interface cleanup on every path.
6. Build, inspect size, and stop for review.

The prototype polls item counts after `CopyHere`. That behavior is only a
reference and may not prove recursive extraction completion. Review the chosen
completion condition rather than copying it blindly.

### Checkpoint 4: execution

1. Add `ShellExecuteExW`.
2. Parse executable path, optional arguments, working directory, and display
   value according to the agreed sequential ABI.
3. Decide whether successful process creation is enough or whether a process
   handle/wait policy is needed. The current goal only requires starting it.
4. Build, inspect size, and stop for review.

## M3: Rust Host Bridge And Injection Recipe

Implemented and awaiting review.

Active Rust additions:

```text
bin/windows-bridge/src/pull/
  mod.rs
  bridge.rs
  parameters.rs
  recipe.rs
```

The milestone adds:

- an explicit `BridgeContract` with the approved magic and independent response
  verification values
- `BridgeHandler<WindowsOs<Driver>, InjectorStatusCode>` dispatch for download,
  extraction, execution, and terminal methods
- a required `PullPolicy` with a maximum download retry count and independent
  extraction and execution permissions
- strict handling of malformed method payloads and packed terminal statuses
- exact little-endian serialization of the conditional sequential parameter ABI
- `bitflags`-backed parameter flags with the guest ABI bit positions kept
  explicit
- one `PullParameters` type with a typestate builder that exposes
  `download_path` only after `download`, extraction only after a complete
  download, and arguments, working directory, and display value only after
  `execute`
- download setters become unavailable after `execute`, so a requested download
  must be completely configured before execution
- no `build` method while an enabled download still lacks its destination path
- a documented caller precondition that parameter strings are accepted by the
  guest APIs; the builders and serializer do not validate empty strings, NUL
  code points, or other content
- compile-time embedding of
  `scfw/build-x64/shellcodes/pull/pull.bin` through `include_bytes!`
- a page-sized combined allocation that begins with the SCFW blob and places
  the parameter block at a `u32`-aligned offset
- `VirtualAlloc`, `RtlFillMemory`, direct guest memory write, and `CreateThread`
  recipe steps
- validation of failed guest calls and `CloseHandle` cleanup for the created
  thread handle
- injector completion when a valid terminal `exit` packet arrives

The user selected independent host permissions for extraction and execution.
The user also selected compile-time shellcode embedding instead of runtime
loading or a Cargo-driven CMake build.
The unified parameter builder is implemented directly rather than through
`bon`, so the type-level operation states remain visible without adding a
procedural macro dependency.

Verification completed:

```text
cargo test -p windows-bridge
    10 passed

cargo +nightly fmt -- --check
    passed

cargo check -p windows-bridge
    passed

cargo clippy -p windows-bridge --all-targets
    passed
```

The check and Clippy runs still report unused and dead-code warnings because M4
has not connected the new modules to `main.rs`; the existing M4 scaffold also
contains unused imports and session state. No live Windows/Xen guest test has
been performed.

## M4: Main Binary

Not started.

`bin/windows-bridge/src/main.rs` currently only:

- configures tracing
- creates the Xen driver/core
- finds the Windows kernel
- loads the ISR profile
- constructs `WindowsOs` and `VmiSession`

It has unused reactor-oriented imports and does not yet:

- parse inputs
- find a target process
- load shellcode
- construct pull parameters
- create a bridge handler
- execute an injection recipe
- report a terminal result

Do not clean up or rewrite `main.rs` until the shellcode and Rust bridge
protocol are reviewed.

## Still-Open Product Decisions

Ask these when M4 begins:

1. Is `windows-bridge` the final package/binary name?
2. Should the CLI use a parser dependency or a small manual parser?
3. What target process should be the default, if any?
4. What download retry count and bridge wait timeout should be defaults?

## Verification Commands

Run SCFW commands from `bin/windows-bridge/scfw`:

```bash
cmake --preset x64
cmake --build --preset x64
```

After the pull target exists, the expected artifact will be under:

```text
bin/windows-bridge/scfw/build-x64/shellcodes/pull/pull.bin
```

Later Rust verification should include:

```bash
cargo +nightly fmt -- --check
cargo check -p windows-bridge
cargo clippy -p windows-bridge
```

Do not claim end-to-end success without a live Windows/Xen guest test.

## Immediate Next Action

Review M3. After approval, start M4 by defining the user-facing inputs and
connecting `PullParameters`, `PullPolicy`, `pull_recipe`, and `PullBridge` to
`InjectorHandler::with_bridge(...)`.
