# Synchronous User-Mode Shellcode Handoff

## Goal

Add a user-mode shellcode recipe that calls the payload on the hijacked guest thread and completes only after the payload returns. Keep the existing CreateThread behavior as an explicitly named spawned recipe.

Use `call` and `spawn` terminology rather than `sync` and `async`. In Rust, `async` implies a `Future`, which neither recipe provides.

## Current State

- The existing user-mode recipe allocates executable memory, materializes its pages, writes the payload, starts it with `CreateThread`, validates the returned handle, and closes the handle.
- The existing kernel-mode recipe directly calls the payload and waits for it to return.
- SCFW x64 payload entry takes two arguments: `entry(void *argument1, void *argument2)`.
- SCFW cleanup tail-jumps to `VirtualFree` or `ExFreePool`, so a directly called payload can free itself and still return to the original caller.
- `UserInjectorHandler` currently enables user hypercall monitoring only after the recipe finishes. This prevents a called payload from using the bridge and leaves a race for spawned payloads that issue a hypercall before recipe completion.

## API Contract

Make a clean API cutover:

- Rename `user_shellcode_recipe` to `user_shellcode_spawn_recipe`.
- Add `user_shellcode_call_recipe`.
- Remove the ambiguous old name. Do not retain an alias or compatibility shim.
- Keep `UserShellcodeRecipeData<Os>` and `UserShellcodeRecipe<Os>` shared by both execution modes.
- Keep all kernel declarations before user declarations.

Extend `shellcode::OsAdapter` in this order:

```rust
fn kernel_shellcode_recipe(...) -> Recipe<Self, Self::KernelRecipeData>;
fn user_shellcode_call_recipe(...) -> Recipe<Self, Self::UserRecipeData>;
fn user_shellcode_spawn_recipe(...) -> Recipe<Self, Self::UserRecipeData>;
```

Expose matching generic root functions in `crates/vmi-utils/src/shellcode/mod.rs`. The root functions must only delegate to the adapter.

Before changing the exported symbol, use LSP references for `user_shellcode_recipe`. Migrate every caller and documentation reference in the same cutover. Existing deploy and msgbox examples retain their behavior by switching to `user_shellcode_spawn_recipe`.

## Recipe Implementation

Primary file:

- `crates/vmi-utils/src/shellcode/os/windows/user_mode.rs`

Factor the shared preparation into one private builder. It should append these steps:

1. Call `VirtualAlloc` for executable guest memory.
2. Validate the allocation and call `RtlFillMemory` to materialize demand-zero pages.
3. Write the payload into guest memory through VMI.

Append one execution-specific suffix:

### Called Recipe

Directly invoke the payload at `guest_address`:

```rust
inject! {
    guest_address(
        parameter, // argument1
        0          // argument2
    )
}
```

The recipe remains active until this call returns. The payload owns its SCFW allocation after control is transferred and frees it through SCFW cleanup. Do not add a host-side free after the call.

### Spawned Recipe

Preserve the existing behavior:

1. Call `CreateThread` with the payload address and parameter.
2. Validate the returned thread handle.
3. Call `CloseHandle`.

Recipe completion means thread creation completed, not payload completion.

### Data Model

Keep one Windows `UserShellcodeRecipeData` type. Its existing `thread_handle` field is used only by the spawned suffix. This is preferable to duplicating the shared preparation or adding a strategy generic for one field.

Keep both implementations in `user_mode.rs` initially. Split the module only if the resulting file becomes materially difficult to navigate.

## Injector Lifecycle Fix

Primary file:

- `crates/vmi-utils/src/injector/os/windows/user_mode.rs`

This change is required for the called recipe. A called payload can issue bridge hypercalls before the recipe returns. Completing the handler while the guest is suspended at that hypercall would prevent the payload from resuming, freeing itself, and returning.

Separate lifecycle state from bridge completion data:

```rust
enum InjectorState {
    PreHijack,
    Executing,
    Teardown(VcpuId),
    Bridge,
    Complete,
}
```

Store these independently on `UserInjectorHandler`:

- A pending bridge completion result.
- Whether user hypercall monitoring is currently enabled.

The explicit monitoring flag is required because monitoring may now be enabled in `Executing`, `Teardown`, or `Bridge`; state alone no longer proves whether cleanup must disable it.

Required transitions:

1. On `PreHijack -> Executing`, enable user hypercall monitoring before starting the first recipe step when the bridge is nonempty.
2. Dispatch bridge hypercalls while the recipe is in `Executing`.
3. If dispatch produces a terminal bridge result during `Executing`, store it but do not transition to `Complete` and do not stop the injector.
4. Resume the guest so the payload can return through SCFW cleanup.
5. When recipe execution finishes, perform the existing register and monitor teardown.
6. After teardown:
   - If a terminal bridge result is pending, disable hypercall monitoring and transition to `Complete`.
   - If the bridge is nonempty and no result is pending, transition to `Bridge`.
   - If the bridge is empty, transition to `Complete` without enabling hypercall monitoring.
7. A terminal result received in `Bridge` may disable monitoring and transition directly to `Complete`.
8. Cleanup must disable user hypercall monitoring exactly when the explicit flag says it is enabled, regardless of lifecycle state.
9. Polling a completed handler must return the stored result with the same externally observable semantics as the current handler.

This also closes the existing spawned-thread race because bridge monitoring is active before `CreateThread` can run the payload.

## Files Expected to Change

- `crates/vmi-utils/src/shellcode/mod.rs`
- `crates/vmi-utils/src/shellcode/os/mod.rs`
- `crates/vmi-utils/src/shellcode/os/windows/mod.rs`
- `crates/vmi-utils/src/shellcode/os/windows/user_mode.rs`
- `crates/vmi-utils/src/injector/os/windows/user_mode.rs`
- User-mode example call sites under `crates/vmi-utils/examples/windows-bridge/`
- README references that still name `user_shellcode_recipe`

Kernel-mode recipe behavior is not part of this change.

## Repository Invariants

- Keep kernel declarations before user declarations.
- Inside `src/shellcode`, use relative `super` paths rather than `crate::shellcode`. Exported macro `$crate::shellcode` paths remain valid.
- Use plain `pub`, not `pub(super)`.
- Preserve all intentional `// REVIEW:` comments, including the one in the file-transfer example.
- Do not add aliases, deprecated exports, or compatibility shims.
- Do not introduce non-ASCII text in code or comments.
- Preserve unrelated staged and unstaged user changes.

## Verification

Run formatting first after implementation:

```text
cargo +nightly fmt
```

Then verify the relevant feature surfaces:

```text
cargo check -p vmi-utils --features shellcode
cargo check -p vmi-utils --features shellcode,arch-amd64,os-windows,bpm
cargo test -p vmi-utils --features shellcode shellcode
cargo test --doc
cargo clippy -p vmi-utils --features shellcode,arch-amd64,os-windows,bpm -- -D warnings
cargo build --example windows-bridge --features arch-amd64,driver-xen,os-windows,utils
```

Exercise these lifecycle scenarios with the strongest available runtime or focused fixture:

1. A called payload with a nonempty bridge emits a terminal hypercall while the recipe is executing, resumes, frees itself, returns, tears down, and only then completes the handler.
2. A spawned payload can issue its first bridge hypercall immediately after `CreateThread` without losing the event.
3. An empty bridge never enables user hypercall monitoring.
4. Error cleanup disables monitoring from every state in which it may be enabled.

If the environment cannot run a Windows VM, report that the guest execution scenario is not runtime-verified. Do not represent compilation or unit tests as proof that the payload returned in a real guest.
