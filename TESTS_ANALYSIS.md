# Test Implementations Analysis

## Executive conclusion

Two different questions have different winners:

1. **Which branch is the more complete committed test deliverable?** `feat/tests`.
   It has substantially broader happy-path coverage, a private shared mock driver
   with its own contract tests, a PTM mock migration, a changelog entry, and a
   reviewable sequence of test/fix commits.
2. **Which branch is the safer correctness baseline?** WIP `6f57693`.
   Its Interceptor and BPM tests are much stronger on failure atomicity,
   rollback, post-error invariants, exact side effects, and successful retry.
   Those tests drove production fixes which `feat/tests` does not contain.

**Overall verdict: WIP is the better correctness implementation, narrowly, but
neither revision should be merged unchanged.** Correctness carries more weight
than raw test count: several `feat/tests` error tests pass while BPM or
Interceptor state is already inconsistent. WIP also has merge blockers, most
notably a retained BPM pending-plus-active removal bug and a multi-definition
page-in rollback hole.

The strongest result is a hybrid:

- start from WIP's Interceptor and BPM transactional production logic;
- port `feat/tests`' broader normal-path tests, pending/active fix,
  `ViewNotFound` cases, global matrix, and shared-driver contract tests;
- implement one strict shared state engine behind narrow component-specific
  driver wrappers;
- add the PTM failure and option-observability tests missing from both.

## Scope and an important repository fact

The comparison used exact revisions:

| Label | Revision |
|---|---|
| Common base | `5693644` |
| WIP | `6f57693` |
| Feature branch | `325df84` (`origin/feat/tests`) |

The request describes the WIP commit as containing shared test support for
Interceptor, BPM, and PTM. **It does not.** Exact WIP `6f57693` contains new
Interceptor and BPM suites plus production fixes. Its PTM suite is byte-for-byte
inherited from `5693644`, and it has no shared mock module.

The main working tree currently contains later, uncommitted
`crates/vmi-utils/src/test_support/` work and migrations of the three wrappers.
That state is outside this commit-to-branch comparison and receives no credit in
the score below. This distinction matters: `feat/tests` is the only compared
revision that actually commits a shared driver and migrates PTM to it.

## Method and observed evidence

The analysis used detached worktrees for all three exact revisions. Five
independent reviews covered the shared mock, Interceptor, BPM, PTM, and all
production deltas. Findings were then checked directly against the revision
sources and by running equivalent commands in both detached trees.

### Test and quality results

| Check | WIP `6f57693` | `feat/tests` `325df84` |
|---|---:|---:|
| `cargo test -p vmi-utils --all-features` | 121 passed | 211 passed |
| Focused Interceptor suite | 19 passed | 46 passed |
| Focused BPM suite | 34 passed | 76 passed |
| Focused PTM suite | 52 passed | 52 passed |
| Shared mock contract suite | none | 21 passed |
| `cargo +nightly fmt -p vmi-utils -- --check` | passed | passed |
| `cargo clippy -p vmi-utils --all-features --tests -- -D warnings` | passed | passed |

The full totals include the same non-component tests and doctests. The focused
counts are the useful comparison. More tests do not automatically mean a more
rigorous suite: `feat/tests` splits many success conditions into small cases,
while WIP combines related state, call-order, rollback, and retry assertions
into scenario tests.

## Summary scorecard

| Dimension | Winner | Reason |
|---|---|---|
| Raw behavioral breadth | `feat/tests` | 46 vs 19 Interceptor tests; 76 vs 34 BPM tests; 21 direct mock tests |
| Failure and rollback rigor | WIP | Checks post-error state, compensation, and retry rather than only `is_err()` |
| Interceptor production correctness | WIP | Fixes `Default`, install rollback, and final-reset retryability |
| BPM production correctness | WIP | Side effects precede state commit; compensation preserves retryability |
| Pending-plus-active BPM behavior | `feat/tests` | Explicitly removes stale pending copies and tears down both states |
| PTM behavioral coverage | Tie | The same 52 named tests and 335 assertions are present |
| PTM infrastructure | `feat/tests`, narrowly | Removes the inline mock and supplies tested shared mechanics, but PTM does not use the new fault/log facilities |
| Mock deduplication | `feat/tests` | One private driver instead of three low-level implementations |
| Mock contract fidelity | WIP, narrowly | Narrow traits, strict errors, exact fault arguments, observable free, fewer permissive no-ops |
| Test organization | WIP | Split model/controller/manager/mock modules instead of 1,862-line and 1,148-line test files |
| Commit reviewability and changelog | `feat/tests` | Incremental test/fix commits and documented behavior; WIP is one broad `wip` commit |
| Overall correctness baseline | WIP | The feature branch's larger suite misses state-corrupting error paths |

## Shared mock driver comparison

### What WIP actually has

WIP uses three capability-specific doubles:

- `MockInterceptorDriver` implements `VmiDriver + VmiRead + VmiWrite +
  VmiViewControl + VmiVmControl`.
- `MockBpmDriver` adds only the protection capability needed by its concrete
  controllers.
- the inherited `MockPtmDriver` implements only `VmiRead +
  VmiQueryProtection + VmiSetProtection`.

Strengths:

- accidental calls to unsupported lifecycle methods fail with `NotSupported`;
- the compiler continues to exercise each component's narrow capability set;
- Interceptor faults match exact arguments such as GFN, offset, view, and
  mapping target;
- attempted failed calls are recorded, not hidden;
- Interceptor free is observable and fails for an unknown frame;
- driver/controller state belongs to the test's driver instance;
- nonuniform pages and checked writes catch offset/copy errors.

Weaknesses:

- page storage, mappings, permissions, allocation, and PTE writes are repeated;
- only Interceptor has strong low-level call and fault observability;
- the PTM double has no call log or fault injection;
- there are no direct tests for common mock mechanics;
- BPM and PTM still have some panic-based setup/write behavior;
- both permission doubles discard `MemoryAccessOptions`.

### What `feat/tests` adds

`crates/vmi-utils/src/mock_driver.rs` is private and registered only under:

```rust
#[cfg(all(test, feature = "arch-amd64"))]
mod mock_driver;
```

This is good production/API hygiene: it is absent from release builds and does
not become a public API. The driver centralizes:

- physical pages and PTE setup;
- view mappings;
- memory permissions;
- deterministic GFN/view allocation;
- successful call recording;
- nth-invocation faults;
- 21 direct contract tests.

This is the better long-term direction. The committed implementation is too
permissive and too broad, however:

1. One `MockDriver` implements the union of every capability for every suite.
   A PTM test can no longer reveal an accidental new dependency on write, view,
   or VM-control capabilities.
2. `pause`, `resume`, view destruction/switching, interrupt injection, and reset
   return success without modeling meaningful state. Unexpected calls can pass.
3. The module claims to record every operation and fault any driver call, but
   `Call`/`Op` omit free, allocate-at, queries, view lifecycle, and VM controls.
4. Faults happen before logging. Error tests cannot prove the attempted GFN,
   view, offset, or chronological failing call.
5. Fault selection is operation-wide (`Op::WritePage`) rather than argument
   specific. A refactor can consume a fault at the wrong write while a generic
   `is_err()` assertion remains green.
6. `free_gfn` is unlogged, unfaultable, and succeeds for an absent frame. This
   can hide a wrong free, double free, or missing cleanup assertion.
7. Out-of-range writes panic, and `write_page_past_end_panics` locks that behavior
   in. The core and Xen driver expose `VmiError::OutOfBounds` instead.
8. Fixture page insertion and allocate-at silently overwrite collisions.
9. The driver hard-codes `4096` and `12` despite being AMD64-specific.
10. `set_memory_access_with_options` discards the options and records the call as
    plain `SetMemoryAccess`.
11. Interceptor tests use `View(0)` and assert remapping. The repository Xen
    driver treats default-view change/reset as successful no-ops, so this is a
    weak model of the primary production backend.
12. BPM controller recording uses thread-local global state. It is isolated
    between test threads, but constructing a second manager on one thread resets
    or shares the first manager's recorder.

### Shared-driver verdict

- **Concept and committed reuse:** `feat/tests` wins.
- **Fidelity of load-bearing error behavior:** WIP wins.
- **Best codebase fit:** neither exact implementation. Use a strict shared
  physical/view/access state engine plus thin Interceptor/BPM/PTM wrappers that
  expose only each component's required traits. Keep controller and PTM
  hierarchy fixtures local.

## Interceptor comparison

### Coverage matrix

| Contract | WIP | `feat/tests` | Verdict |
|---|---|---|---|
| Empty construction and `Default` | Tests both with a non-`Default` driver | Uses only `new()` | WIP |
| First insertion/copy/mapping/calls | One dense test with nonuniform full-page state and exact calls | Five granular tests, mostly uniform pages | WIP, slight |
| Valid endpoint offsets | Last byte | Offset zero and last byte | `feat/tests` |
| Actual cross-page rejection | Custom architecture with a two-byte breakpoint | AMD64 one-byte success only | WIP |
| Duplicate/reference counting | Exact no-call behavior and final sequence | More granular cases including three references | Tie |
| Multiple offsets/pages/views | Strong state and event isolation | Equally broad, more separate cases | Tie |
| Unknown/force removal | Asserts no driver effects | More individual result-shape cases | WIP, slight |
| Shadow refresh/reuse | Full refresh and exact reactivation sequence | Also removes again to prove newly captured original bytes | `feat/tests`, slight |
| Event matching | Software event plus combined negative matrix | Eleven cases, including hardware `#BP` vs software INT3 | `feat/tests` |
| Activation/install failures | Every allocate/read/copy/write/map/patch stage, cleanup, and retry | Six propagation tests; several stop at `is_err()` | WIP |
| Final removal failures | Restore failure and reset failure preserve state and retry | Restore error only; reset failure omitted | WIP |

### WIP's material production fixes

In `6f57693:crates/vmi-utils/src/interceptor.rs`:

1. **Manual `Default`.** `#[derive(Default)]` imposed an unnecessary
   `Driver: Default` bound. WIP delegates manually to `new()` and tests it with a
   non-`Default` mock.
2. **Initial activation cleanup.** If original read, full-page copy, or remap
   fails before registration, WIP attempts to free the allocated frame and
   leaves no tracked page or mapping.
3. **Breakpoint-install rollback.** If shadow reread or breakpoint write fails
   after activation, WIP resets the newly active mapping and keeps the empty page
   available for a clean retry.
4. **Retryable final removal.** WIP restores bytes, attempts the final mapping
   reset before deleting bookkeeping, and re-patches the breakpoint if reset
   fails. A later removal can retry.

The tests verify physical bytes, mapping, logical membership, attempted calls,
and a successful retry. This is stronger than merely verifying error
propagation.

### `feat/tests` strengths and remaining defects

`feat/tests` has excellent normal-path granularity and event classification. Its
unique production choice inserts the empty page into Interceptor state before
activation. A failed activation retains and reuses the allocated GFN rather
than relying on best-effort free. This avoids losing track of a frame if free
itself fails, at the cost of retaining a resource when no insertion ever
succeeds.

It leaves two higher-severity base defects unchanged:

1. A post-activation shadow-read or patch-write error can return `Err` while the
   guest view remains mapped to an empty logical Interceptor page. The named
   patch-write test only checks `is_err()`.
2. Final removal deletes breakpoint bookkeeping before `reset_view_gfn`. A
   reset error leaves the mapping active but makes a retry return `None`.
   `Op::ResetView` exists in the mock, but no Interceptor test uses it.

Additional test weaknesses:

- the initial full shadow-copy write and post-activation shadow read are not
  faulted;
- failed calls are absent from the log;
- comments claiming retryability are not always followed by an actual retry;
- uniform fill pages are less sensitive to copy permutation errors;
- there is no true multi-byte cross-page rejection case.

### Interceptor verdict

**WIP wins.** `feat/tests` is the better catalog of ordinary behavior, but WIP
specifies and implements the harder invariant: after an error, guest mapping,
shadow bytes, and Interceptor bookkeeping remain mutually consistent and the
operation can be retried.

High-value ports from `feat/tests` into WIP:

- hardware-exception `#BP` negative event;
- offset-zero insertion;
- explicit three-reference progression;
- removal after refreshed reinsertion;
- granular happy-path names where diagnosis improves;
- tracked-GFN recovery if cleanup free fails.

## BPM comparison

### Coverage matrix

| Contract | WIP | `feat/tests` | Verdict |
|---|---|---|---|
| Breakpoint builder/identity | Four tests, all identity fields and builder orders | Two direct builder tests | WIP |
| Active insert/order/reference sharing | Dense state/query/call assertions | More page/context shapes and concrete call cases | Tie |
| Exact tag lifecycle | Active and pending tags removed individually | Stores multiple tags but removal is key-wide and untested for tag survival | WIP, subject to API decision below |
| Pending key isolation | Behavior follows exact definitions; no dedicated multi-key pending test | Explicit active and pending key-isolation tests | `feat/tests` |
| Pending plus active coexistence | Retains inherited early-return leak | Drops exact pending copy on activation and tears down both | `feat/tests` |
| Translation active/pending/error dispatch | Covers both states and non-translation errors | More symmetric insert/remove cases | `feat/tests`, slight |
| Page-in/page-out success | Round-trip, no-op, and batch behavior | Broader individual happy paths | Tie |
| Page-in/page-out failure | Preserves state and retries | No failure tests | WIP |
| View/index/clear lifecycle | Propagates failures and commits state after teardown | Broader happy paths, but teardown can pre-delete state | WIP |
| Event lookup/removal results | Dense combined cases | More explicit result-shape cases | `feat/tests`, slight |
| Global breakpoints | Correct stored canonical context and same-GFN reference counts | Much broader global matrix | Tie, with different gaps |
| `ViewNotFound` teardown | Behavior preserved but not directly tested | Explicit uninstall and unmonitor tests | `feat/tests` |
| Concrete controllers | Five dense lifecycle tests | Fifteen granular controller tests | `feat/tests` |
| Install/monitor/remove/unmonitor faults | Post-state, compensation order, and retry | Mostly `is_err()` only | WIP |

### Why WIP is stronger on BPM correctness

WIP moves the controller boundary into a transactional order:

1. install the physical breakpoint;
2. monitor a newly occupied page;
3. only then publish all coupled maps and indexes.

Removal does the inverse external work before deleting manager state. If the
second step fails, WIP compensates by removing or reinserting the physical
breakpoint. Group/page transitions restore already processed controller items
before returning an error.

The tests `insertion_failure_leaves_no_active_state`,
`monitor_failure_rolls_back_installation_and_state`,
`removal_failure_keeps_breakpoint_active`,
`unmonitor_failure_restores_breakpoint_for_retry`,
`page_in_failure_preserves_pending_state`, and
`page_out_failure_preserves_active_state` check the resulting state and retry.

By contrast, `feat/tests` production generally mutates active, global, and
reverse-index state before fallible controller operations. Tests such as
`insert_propagates_controller_install_error`,
`insert_propagates_monitor_error`, and
`remove_propagates_other_error_from_uninstall` usually prove only that an error
was returned. They permit these states:

- logical active state published when physical installation failed;
- physical installation and logical state retained when monitoring failed, so a
  retry returns duplicate without repairing monitoring;
- active/global/index state removed when physical uninstall failed, so the
  installed breakpoint is no longer discoverable or retryable;
- pending state deleted before a fallible active install/removal.

### Confirmed static blocker in `feat/tests`: global root normalization

In `325df84:crates/vmi-utils/src/bpm/mod.rs`, insertion canonicalizes a local
`ctx` used as the bucket key but inserts the original root-bearing `Breakpoint`
into the definition set. Inserting the same global VA/key/tag from a second
root can therefore return idempotent `false` while still adding a second stored
definition.

Consequences established by the control flow:

- direct removal from the second root looks up the noncanonical context and can
  miss the active bucket;
- page-out can split supposedly identical global definitions into separate
  pending roots;
- `global_breakpoint_second_root_same_page_is_idempotent` misses the defect
  because it checks return value and controller call count, not stored
  definition count or direct removal.

WIP normalizes the complete stored `Breakpoint`, avoiding this mismatch.

### WIP BPM blockers and ambiguities

WIP is not complete:

1. **Pending plus active leak.** Insert a definition as pending, then insert the
   same definition with an active physical hint. WIP does not drop the pending
   copy. `remove_with_hint` removes pending and returns early, leaving the
   installed active breakpoint. `feat/tests` explicitly fixes and tests this.
2. **Multi-definition page-in error.** WIP removes the whole pending set before
   iterating. On the first failed activation it restores the failed item and
   already activated items, but any not-yet-visited definitions are dropped.
   The test covers one pending definition only.
3. **Exact tag removal changes inherited semantics.** `Breakpoint` equality and
   hash include tag, the API accepts a full breakpoint definition, and WIP tests
   tag-by-tag removal. The base implementation and `feat/tests` treat the
   `(key, context)` bucket as removal identity. The public docs do not state
   clearly whether tag is identity or metadata. Exact removal is the better
   reading of the current type/API, but this should be decided and documented
   before merge rather than changed accidentally.
4. Neither suite covers a global multi-root PTM page-out/page-in round trip.
   [INFERENCE] Fully canonicalizing stored definitions may lose original-root
   provenance needed by a future transition design.
5. Partial group rollback is not exercised by failing the second of multiple
   controller operations.

### BPM verdict

**WIP wins overall because manager invariants and retryability are load-bearing.**
`feat/tests` wins on normal-path breadth and fixes a real WIP omission. Port its
pending/active cases without discarding WIP's controller-first/state-last
ordering or exact-definition behavior.

## PTM comparison

### Attribution

- Base `5693644` and WIP `6f57693` contain the identical PTM test blob.
- WIP adds zero PTM tests and changes no PTM production code.
- `feat/tests` preserves all 52 named PTM tests and their assertion bodies while
  replacing the 119-line local `MockPtmDriver`/PTE helper block with the shared
  `MockDriver`.
- `feat/tests` also changes no PTM production code.

Therefore:

- **behavioral coverage: tie**;
- **attributable PTM work: `feat/tests` wins**, but only for infrastructure;
- the shared migration neither adds nor removes PTM behavior coverage.

### Strong common coverage

Both suites cover:

- monitor/unmonitor/reference lifecycles;
- absent entries at every hierarchy stage through the page-in/out scenarios;
- independent roots and views;
- shared page-table pages;
- PFN changes at PML4, PDPT, PD, and PT levels;
- page-in/out and subtree rebuilds;
- dirty ordering, deduplication, and per-vCPU state;
- 2 MiB and 1 GiB large-page transitions;
- the `walk_subtree` cached-PTE regression.

### Gaps shared by both

1. `MemoryAccessOptions` are discarded. Production requires
   `IGNORE_PAGE_WALK_UPDATES`, but replacing the options setter with a plain
   setter would leave all PTM tests green.
2. No PTM test uses the feature mock's read/set-access fault injection.
3. No monitor-construction rollback, permission failure/restore failure, dirty
   reread failure, or retry behavior is specified.
4. Several event tests assert only variant/count/context, not exact view,
   context, old/new physical address, and cardinality.
5. The multi-vCPU tests use `VcpuId(1)` while both mock metadata implementations
   report one vCPU.
6. Large-page fixtures use misaligned GFNs and a low VA, so they do not exercise
   realistic 2 MiB/1 GiB alignment and upper offset bits.
7. Permission-change coverage mainly changes accessed/dirty bits, not a broad
   matrix of RW/US/NX behavior.
8. The Bug #3 regression checks a root-2 PageOut/PageIn exists, but not the exact
   new physical address or absence of spurious events.

Potential production risks not exercised by either suite:

- [INFERENCE] a later-level monitor read/protection error may retain earlier
  table references and read-only permissions because construction is
  incremental and has no rollback guard;
- [INFERENCE] dirty work may be lost when `process_dirty_entries` removes a
  vCPU's dirty set before a fallible reread;
- [INFERENCE] a restore failure may be forgotten after the monitor removes the
  table record needed for retry.

### PTM verdict

**Tie on test rigor; `feat/tests` wins narrowly on maintenance.** It preserves
the complete inherited suite and removes duplicate mechanics. The win is small
because PTM does not consume the shared driver's new call/fault facilities, the
options contract remains invisible, and the all-capabilities driver weakens
compile-time boundary checking.

## Production change comparison

| Behavior | WIP | `feat/tests` |
|---|---|---|
| Interceptor `Default` without `Driver: Default` | fixed and tested | inherited defect |
| Initial Interceptor activation failure | frees and removes unregistered shadow | retains and reuses tracked shadow |
| Interceptor post-activation install rollback | fixed and tested | inherited side effect |
| Interceptor final reset retryability | fixed and tested | inherited defect |
| BPM pending-only view result | fixed | fixed |
| BPM stale pending view index on clear | fixed | fixed |
| BPM missing-key removal result | fixed | fixed |
| BPM global GFN reference counting | fixed | fixed |
| BPM exact tag removal | fixed, but contract needs documentation | key-wide removal |
| BPM pending copy dropped on activation | not fixed | fixed and tested |
| BPM pending plus active combined removal | not fixed | fixed for success path |
| BPM controller failure transactions | fixed and tested | inherited corruption paths |
| BPM global stored-root canonicalization | consistent | inconsistent stored definition |
| PTM production | unchanged | unchanged |
| Test support in production/public API | none | none; correctly test-gated/private |
| Changelog | no entry | documents fixes |
| Unrelated source churn | bridge formatting and lockfile ancestry | less unrelated churn |

## What one implementation has that the other does not

### WIP-only strengths

- usable generic `Interceptor::default()`;
- true multi-byte cross-page test with an unreachable driver;
- nonuniform full-page copy assertions;
- exact-argument faults and attempted-failure call logs;
- observable strict shadow free;
- Interceptor install/reset rollback and retry tests;
- BPM controller-first/state-last transactions;
- BPM compensation and retry tests;
- exact active and pending tag removal tests;
- driver-instance BPM controller recorder;
- split test modules organized by model, controller, manager, and mock;
- canonical stored global breakpoint contexts.

### `feat/tests`-only strengths

- committed shared mock driver used by all three suites;
- 21 direct shared-driver contract tests;
- substantially broader granular success/negative matrices;
- offset-zero and hardware `#BP` Interceptor cases;
- explicit pending-key isolation;
- stale pending copy removal on activation;
- pending-plus-active combined removal on success;
- explicit tolerated `ViewNotFound` teardown tests;
- much broader global-breakpoint combinations;
- more concrete BreakpointController and MemoryController cases;
- both GFN and V2P caches disabled in BPM fixtures;
- incremental test/fix commits and changelog documentation.

## Recommended convergence plan

### Must fix before taking either production patch

1. Port `feat/tests`' pending-to-active deduplication into WIP.
2. Change WIP explicit removal to attempt exact pending and exact active teardown
   without early return.
3. Preserve every not-yet-visited pending definition on multi-item page-in
   failure.
4. Keep WIP's controller-first/state-last BPM ordering and compensation.
5. Keep WIP's complete Interceptor mapping/bookkeeping rollback.
6. Fix feature global insertion by normalizing the stored breakpoint, not only
   the bucket key.
7. Decide and document whether `Tag` participates in removal identity.

### Shared test support

Build one strict shared state engine, but retain thin suite wrappers:

- Interceptor wrapper: read/write/view/VM control only, exact call/fault
  assertions, free observability.
- BPM wrapper: only capabilities required by concrete controllers, with
  per-instance controller recording.
- PTM wrapper: read/query/set protection only.

The engine should:

- use `Amd64::PAGE_SIZE` and `PAGE_SHIFT`;
- reject page/allocation collisions;
- return `VmiError::OutOfBounds` instead of panicking;
- record attempted calls before fault injection;
- include argument-specific and nth-invocation fault matching;
- log/fault strict free and allocate-at;
- distinguish plain and option-bearing protection calls and retain options;
- return `NotSupported` for lifecycle operations it does not model;
- use real non-default views in remap tests;
- keep PTM PTE/hierarchy builders and component event helpers local.

### Tests to port or add first

1. All WIP Interceptor fault/retry tests and custom cross-page test.
2. Feature Interceptor hardware-event, offset-zero, and refreshed-remove cases.
3. All WIP BPM rollback/retry tests.
4. Feature BPM pending/active, `ViewNotFound`, global, and concrete-controller
   cases, strengthened to assert post-state and retry on failures.
5. A second-operation failure in multi-breakpoint insert/remove/page-in/page-out
   groups.
6. Global multi-root/multi-GFN PTM page-out/page-in round trips.
7. PTM exact option call assertions for `IGNORE_PAGE_WALK_UPDATES`.
8. PTM monitor and dirty-processing fault/retry tests.
9. Realistically aligned 2 MiB/1 GiB large-page fixtures with exact event fields.

## Final recommendation

Do not choose either branch wholesale.

If one revision must be the base, choose **WIP `6f57693`** because its production
state transitions remain coherent across more failures, and its tests prove
recovery rather than merely error propagation. Before merge, fix its
pending-plus-active and multi-definition page-in holes.

Then port the best of `feat/tests`: the private shared-test direction, direct
mock contracts, broader happy-path matrix, pending/active behavior,
`ViewNotFound` cases, global/controller coverage, changelog, and granular commit
structure. Repair the shared mock before making it authoritative across three
suites; otherwise one inaccurate driver contract will make all three components
agree with the mock rather than with the production backend.
