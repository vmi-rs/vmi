# Shared VMI Test Support Plan

## Goal

Deduplicate the physical-memory, view-mapping, permission, allocation, call-recording, and fault-injection mechanics used by the PTM, Interceptor, and BPM tests without weakening their behavioral specifications or broadening production APIs.

Each test must continue to create fresh state. This work shares an implementation, not a process-wide driver instance.

## Decision

Create private, test-only support inside `vmi-utils` rather than a new workspace crate:

```text
crates/vmi-utils/src/test_support/
    mod.rs
    amd64.rs
```

Register it from `crates/vmi-utils/src/lib.rs` only when tests and the AMD64 feature are enabled:

```rust
#[cfg(all(test, feature = "arch-amd64"))]
mod test_support;
```

The shared layer will provide an `Amd64TestVm` state engine. PTM, Interceptor, and BPM will retain thin component-specific driver wrappers that implement only the VMI traits required by that component.

Do not create a capability-complete driver used directly by every suite. Narrow wrappers preserve compile-time detection of accidental trait-bound expansion and keep component-specific call assertions clear.

## Current overlap

All three suites model guest physical pages. Interceptor and BPM also model view mappings and deterministic GFN allocation. PTM and BPM model memory permissions. Interceptor records and faults low-level driver operations, while BPM separately records and faults `TapController` operations.

The compatible shared state is:

- guest pages keyed by GFN;
- explicit `(View, Gfn) -> Gfn` mappings;
- memory permissions keyed by `(View, Gfn)`;
- the next allocatable GFN;
- a typed low-level driver call history;
- one typed, one-shot low-level driver fault.

The following remain local because they describe component scenarios rather than driver mechanics:

- PTM page-table layouts, large-page entries, dirty-entry scenarios, and PTM event expectations;
- Interceptor breakpoint events, breakpoint-specific constants, and the synthetic cross-page architecture;
- BPM breakpoint builders, event fixtures, `TapController` doubles, controller calls, and controller faults.

## Shared support design

### `crates/vmi-utils/src/test_support/mod.rs`

- Document the module as private support for deterministic VMI unit tests.
- Declare the AMD64 support module.
- Re-export only the types needed by sibling test modules.

### `crates/vmi-utils/src/test_support/amd64.rs`

Add `Amd64TestVm` with private interior-mutable state and crate-visible methods.

#### Setup and inspection methods

Provide explicit operations for:

- constructing empty state with an explicit first allocatable GFN;
- inserting initialized and zero-filled pages;
- replacing a page;
- reading a copied page for assertions;
- checking page existence;
- writing setup bytes without recording a driver call;
- writing an AMD64 page-table entry;
- inspecting a view mapping;
- inspecting and initializing memory permissions;
- configuring one matching low-level fault;
- reading and clearing chronological low-level calls.

Setup methods must reject duplicate pages and invalid page sizes. Byte writes used through VMI traits must return `VmiError::OutOfBounds` rather than panic.

#### Driver operations

Provide shared methods used by the thin wrappers for:

- `VmiDriver::info` data;
- page reads and writes;
- permission queries and updates, including option-bearing variants;
- view mapping changes and resets;
- GFN allocation and freeing.

Keep unsupported lifecycle operations in the component wrappers. They should continue returning `VmiError::NotSupported`.

#### Calls and faults

Move the Interceptor driver's low-level `Call` and `Fault` concepts into shared types named `DriverCall` and `DriverFault`.

The initial variants should be exactly the operations currently observed or faulted:

- allocate and free;
- read;
- write with GFN, offset, and byte count;
- change a view mapping;
- reset a view mapping.

Preserve the current Interceptor timing semantics:

- reads, writes, mapping changes, and mapping resets are recorded before a matching fault is returned;
- failed allocation is not recorded as a successful allocation;
- successful allocation creates a zero-filled page before returning;
- freeing records the call and removes the page;
- a configured fault is consumed only by an exactly matching operation.

Enable call recording only for Interceptor and direct state-engine tests. BPM
and PTM use the same operations without retaining unused call histories.

Do not merge BPM's `ControllerCall` or `ControllerFault` into these types. Controller operations are not `VmiDriver` operations.

#### Direct contract tests

Before migrating a component wrapper, add focused tests for `Amd64TestVm`
itself. These tests must exercise the helper through its crate-visible API
rather than inspect private fields.

Cover:

- initialized and zero-filled page setup;
- page reads, writes, and out-of-bounds errors;
- memory permissions, including option-bearing updates;
- view mapping changes and resets;
- deterministic allocation and freeing;
- chronological call recording;
- exact one-shot fault matching;
- call-recording timing for successful and failed operations.
- disabled call recording for suites that do not assert low-level operations.

The component suites remain the integration proof that the shared engine
implements the required VMI behavior. The direct tests isolate failures in the
test harness before three component suites depend on it.

## Implementation sequence

### 1. Establish the baseline

Run the three focused suites before editing and retain their pass counts and output:

```text
cargo test -p vmi-utils --features arch-amd64,ptm --lib ptm::arch::amd64_tests
cargo test -p vmi-utils --features arch-amd64,interceptor --lib interceptor::tests
cargo test -p vmi-utils --features arch-amd64,bpm --lib bpm::tests
```

This refactor must not change the behavioral contract represented by those suites.

### 2. Add the shared engine and migrate Interceptor

Files:

- `crates/vmi-utils/src/lib.rs`
- `crates/vmi-utils/src/test_support/mod.rs`
- `crates/vmi-utils/src/test_support/amd64.rs`
- `crates/vmi-utils/src/interceptor/tests/mock.rs`
- Interceptor test files that import the old `Call` or `Fault` names

Actions:

1. Add `Amd64TestVm`, `DriverCall`, and `DriverFault` using the Interceptor mock's checked I/O, chronological call recording, and exact fault behavior as the canonical starting semantics.
2. Add and run the direct `Amd64TestVm` contract tests before any component wrapper uses the shared engine.
3. Keep `MockInterceptorDriver` as a thin local wrapper containing `Amd64TestVm`.
4. Keep its existing VMI capability set: `VmiDriver`, `VmiRead`, `VmiWrite`, `VmiViewControl`, and `VmiVmControl`.
5. Forward supported operations to the shared engine and keep unsupported methods local.
6. Keep Interceptor constants, event constructors, page-content helpers, and assertions in the Interceptor test module.
7. Remove the duplicated page, mapping, allocation, call, and fault state from the local wrapper in the same cutover.
8. Run the focused Interceptor suite and verify that exact call-order and retry tests remain unchanged in meaning.

### 3. Migrate BPM

Files:

- `crates/vmi-utils/src/bpm/tests/mock.rs`
- BPM test files only where shared type imports require adjustment

Actions:

1. Replace BPM's duplicated pages, mappings, permissions, read fault, and next-GFN fields with `Amd64TestVm`.
2. Keep `MockBpmDriver` as a thin wrapper implementing only its current traits: `VmiDriver`, `VmiRead`, `VmiWrite`, `VmiSetProtection`, `VmiViewControl`, and `VmiVmControl`.
3. Keep `ControllerCall`, `ControllerFault`, their storage, and `MockController` local to BPM.
4. Preserve BPM's setup helpers and public test vocabulary where it improves readability. Small wrapper methods may delegate to `Amd64TestVm` so scenario tests do not expose shared-state internals.
5. Standardize the shared mapping key order as `(view, gfn)`. Local adapters may preserve an existing test helper signature if changing it would add noise without clarifying behavior.
6. Keep BPM's address-translation hierarchy and event builders local.
7. Remove the replaced state and trait-operation logic in the same cutover.
8. Run the focused BPM suite, paying particular attention to controller rollback, Interceptor-backed controller behavior, shadow mappings, and permission restoration.

### 4. Migrate PTM

Files:

- `crates/vmi-utils/src/ptm/arch/amd64_tests.rs`

Actions:

1. Replace PTM's page and access maps with `Amd64TestVm`.
2. Keep a thin `MockPtmDriver` implementing only `VmiDriver`, `VmiRead`, `VmiQueryProtection`, and `VmiSetProtection`.
3. Forward page and permission operations to the shared engine.
4. Use the shared low-level PTE write operation, but keep the hierarchy builders and PTE-shape helpers local so each PTM scenario remains readable.
5. Remove the old inline driver state and duplicated trait mechanics in the same cutover.
6. Run the focused PTM suite, including multi-vCPU dirty tracking, large pages, view isolation, and failure/error cases.

### 5. Verify the complete cutover

After all three focused suites pass, run:

```text
cargo +nightly fmt -p vmi-utils -- --check
cargo clippy -p vmi-utils --all-features --tests -- -D warnings
cargo test -p vmi-utils --all-features
```

Review the final test support from the perspective of a test author:

- each test creates independent state;
- component wrappers expose no extra VMI traits;
- low-level driver calls and BPM controller calls remain distinct;
- component scenarios do not reach through several abstraction layers to arrange memory;
- no obsolete mock state, aliases, compatibility wrappers, or unused helpers remain;
- production builds, public APIs, feature definitions, and normal dependencies are unchanged.

## Acceptance criteria

- PTM, Interceptor, and BPM use the same `Amd64TestVm` implementation for overlapping state and operations.
- Each suite retains a narrow local driver type with its original VMI capability set.
- Every existing behavioral test passes without weakening assertions.
- Interceptor call-order and fault-injection behavior is preserved exactly.
- BPM controller fault injection remains local and independent from low-level driver faults.
- PTM hierarchy construction remains explicit enough that its tests continue to specify page-table behavior.
- No global or shared mutable singleton is introduced.
- No new workspace crate, Cargo dependency, public feature, or published API is introduced.
- Full `vmi-utils` formatting, linting, and tests pass.

## Risks and controls

### Shared helper becomes a god object

Control: keep `Amd64TestVm` limited to reusable VMI mechanics. Scenario builders, events, controllers, and component constants stay local.

### Extra trait implementations hide dependency growth

Control: VMI traits remain implemented on narrow component wrappers, not directly on one capability-complete shared driver.

### Refactor changes mock semantics

Control: migrate Interceptor first and treat its checked I/O, call timing, and exact fault consumption as explicit contracts. Run each focused suite immediately after its migration.

### Shared abstraction makes tests harder to reconstruct from

Control: preserve local test vocabulary and explicit scenario setup. The shared layer should remove storage plumbing, not hide page-table layouts or breakpoint lifecycle operations.

## Future extraction trigger

Create `crates/vmi-test-support` only when at least one other workspace crate needs the same state engine. If extracted:

- name the crate `vmi-test-support`;
- set `publish = false` explicitly because the workspace default is publishable;
- keep it as a dev-dependency of published crates;
- depend only on lower-level crates such as `vmi-core` and `vmi-arch-amd64`;
- keep all `vmi-utils`-specific controllers and fixtures in `vmi-utils` to avoid a dependency cycle;
- run `cargo package` for affected published crates as part of verification.

Publishing should be reconsidered only if downstream users are expected to rely on the test driver as a supported, versioned API.
