# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `InjectorResultCode` renamed to `InjectorStatusCode`.
- **Breaking:** `WindowsDirectoryObject::lookup` now traverses
  `\`-separated paths instead of matching a single-component name. Name
  comparison is ASCII-case-insensitive. Per-bucket read errors are
  skipped instead of aborting the search. For the previous
  single-component behavior, use `WindowsDirectoryObject::child`.
- **Breaking:** PE header types now live in `crate::pe` as `#[repr(C, packed)]`
  zerocopy mirrors of `object::pe`'s `IMAGE_*` layouts. `ImageDosHeader`,
  `ImageNtHeaders`, `ImageFileHeader`, `ImageDataDirectory`,
  `ImageDebugDirectory`, `ImageRuntimeFunctionEntry`, and
  `ImageSectionHeader` expose bare scalar fields (`u16`, `u32`, `u64`)
  instead of `object`'s endian wrappers, so call sites use direct field
  access in place of `.get(LE)`.
- **Breaking:** `ImageNtHeaders::file_header()` / `optional_header()`
  accessors removed - read the `file_header` / `optional_header` fields
  directly. The macro-generated `ImageFileHeader` accessors
  (`number_of_sections()`, `time_date_stamp()`, ...) are likewise
  replaced by public fields.
- `Export`, `ExportTable`, `ExportTarget`, and the
  `IMAGE_DIRECTORY_ENTRY_*` / `IMAGE_DEBUG_TYPE_*` / `IMAGE_DOS_SIGNATURE` /
  `IMAGE_NT_*` constants are re-exported from `crate::pe`, so callers no
  longer need to depend on `object::pe` directly.

### Added

- `WindowsDirectoryObject::child` for a direct single-component lookup
  within a directory.
- `WindowsOs::lookup_object` for resolving an absolute object-namespace
  path from the root directory.
- `WindowsKernelProcessorBlock::processor_context_frame` exposing
  `_KPRCB.ProcessorState.ContextFrame` directly.
- `WindowsUnloadedDriver` accessor for `_UNLOADED_DRIVERS` records.
- `WindowsOs::unloaded_modules` iterator over `MmUnloadedDrivers`
  and `MmLastUnloadedDriver`.
- `WindowsOs::kernel_build_number` exposing `NtBuildNumber`.
- Registry hive walking:
  - `WindowsHive` wraps `_CMHIVE`, with cell
    resolution through `WindowsHiveMapDirectory` / `WindowsHiveMapTable` /
    `WindowsHiveMapEntry` and `WindowsHiveCellIndex` /
    `WindowsHiveStorageType`.
  - `WindowsKeyNode` (`_CM_KEY_NODE`), `WindowsKeyIndex` (`_CM_KEY_INDEX`),
    and `WindowsKeyValue` (`_CM_KEY_VALUE`) with `WindowsKeyValueData`,
    `WindowsKeyValueFlags`, and `WindowsKeyValueType`, for reading
    registry keys and values out of a hive.
  - `KeyControlBlockIterator`, `KeyNodeIterator`, and `KeyValueIterator`
    for walking the KCB cache, subkeys, and values.
  - `WindowsOs::hives` iterator over loaded hives, sourced from
    `CmpHiveListHead`.
  - `WindowsOs::lookup_key` / `WindowsHive::lookup`.
- Access tokens:
  - `WindowsToken` for `_TOKEN` objects.
  - `WindowsTokenFlags` bitflags for `_TOKEN.TokenFlags`.
  - `WindowsTokenType` and `WindowsImpersonationLevel` enums for
    `_TOKEN_TYPE` and `_SECURITY_IMPERSONATION_LEVEL`.
  - `WindowsTokenSource` accessor for `_TOKEN_SOURCE`.
  - `WindowsPrivilege` for `_LUID` privileges.
  - `WindowsTokenPrivilege` for `_SEP_TOKEN_PRIVILEGES` entries.
  - `WindowsProcess::token` resolving `_EPROCESS.Token`.
  - `WindowsThread::impersonation_token` resolving
    `_ETHREAD.ClientSecurity.ImpersonationToken`,
    gated on `_ETHREAD.ActiveImpersonationInfo`.
- Security identifiers:
  - `WindowsSid` accessor for `_SID`.
  - `WindowsSidAndAttributes` accessor for `_SID_AND_ATTRIBUTES`.
  - `WindowsSidAttributes` bitflags covering the `SE_GROUP_*`
    attribute bits.
- `WindowsLuid` value type for `_LUID`.

### Fixed

- `WindowsSession::id()` and `WindowsSession::processes()` on Windows 11
  24H2, where `_MM_SESSION_SPACE` was replaced by `_PSP_SESSION_SPACE`
  and its fields are no longer exposed in PDB symbols. The
  `SessionId` and `ProcessList` offsets are now hardcoded.

## [0.6.0] - 2026-04-20

### Changed

- **Breaking:** `WindowsHandleTable::iter` now returns
  `impl Iterator<Item = Result<(u64, WindowsHandleTableEntry<'a, Driver>), VmiError>>`
- `WindowsDirectoryObject::iter` is now lazy
- **Breaking:** `StackUnwind` trait renamed to `Unwinder`,
  `StackUnwindAmd64` renamed to `UnwinderAmd64`, and `StackFrame`
  renamed to `Frame`.
- **Breaking:** `Unwinder::unwind` (and `unwind::amd64::unwind_leaf`)
  now return `Result<Unwound, VmiError>` instead of
  `Result<Option<StackFrame>, VmiError>`.

### Added

- `WindowsThread::next_processor` exposing `_KTHREAD.NextProcessor`.
- `WindowsThread::alertable` exposing `_KTHREAD.Alertable`.
- `WindowsThread::wait_mode` exposing `_KTHREAD.WaitMode` as a
  `WindowsProcessorMode` enum.
- `WindowsThread::wait_reason` exposing `_KTHREAD.WaitReason` as a
  `WindowsThreadWaitReason` enum.

### Fixed

- Iterator-returning methods now use Rust 2024 `use<...>` precise
  capturing bounds, so the returned iterators are no longer tied to
  the lifetime of the receiver borrow. Affects `VmiOs::modules` /
  `processes`, `VmiOsProcess::regions` / `threads`, all three
  `WindowsPebLdrData` module-order walkers, `WindowsDirectoryObject::iter`,
  `WindowsSession::processes`, and the corresponding Windows and Linux
  implementations. Enables patterns such as `vmi.os().modules()?`
  where the iterator outlives the temporary `VmiOsState`.
- `BreakpointManager::get_by_event` migrated from `+ '_` to
  `+ use<'_, Key, Tag>` for consistency.
- `vmi-macros` now carries precise-capture bounds through
  `derive_os_wrapper` and `derive_trait_from_impl` expansion,
  rewriting `Self` to `Os` in the generated `VmiOsState` wrappers and
  appending the macro-introduced `'__vmi` lifetime (and `Self`) to
  every copied `use<...>` list as Rust 2024 requires.

## [0.5.1] - 2026-04-18

### Fixed

- docs.rs build

## [0.5.0] - 2026-04-18

### Changed

- **Breaking:** `VmiOs` trait no longer takes a `Driver` generic parameter;
  `Driver` is now an associated type (`type Driver: VmiDriver`), along with
  `type Architecture: Architecture`. This eliminates the redundant
  `<Driver, Os>` pair from all context types (`VmiSession`, `VmiState`,
  `VmiContext`, `VmiHandler`), which now only require `<Os>`.
- **Breaking:** `read_wstring*` methods renamed to `read_string_utf16*`
  (`read_wstring` -> `read_string_utf16`, `read_wstring_bytes` ->
  `read_string_utf16_bytes`, and their `_limited` / `_in` variants)
- **Breaking:** `VmiDriver` split into a base trait and composable sub-traits
    - `VmiRead`, `VmiWrite`, `VmiQueryProtection`, `VmiSetProtection`,
      `VmiQueryRegisters`, `VmiSetRegisters`, `VmiViewControl`,
      `VmiEventControl`, `VmiVmControl`
    - Context types (`VmiOs`, `VmiSession`, `VmiState`, `VmiContext`,
      `VmiHandler`) relaxed to `VmiDriver`, with methods gated behind the
      minimal bounds they require
    - Dump drivers now only implement `VmiDriver`, `VmiRead`, and
      `VmiQueryRegisters`
- **Breaking:** `WindowsThread::attached_process()` renamed to
  `WindowsThread::current_process()`
- **Breaking:** `InjectorHandler` now accepts `VmiSession` instead of `VmiCore`
- **Breaking:** `InjectorHandler` refactored into a generic delegation wrapper
  with `ExecutionMode`-based dispatch
- **Breaking:** Bridge trait hierarchy restructured: `BridgeHandler` split into
  `BridgeContract` (magic/verification constants), `BridgeHandler` (per-request
  handling), and `BridgeDispatch` (packet routing). The `Bridge` generic
  parameter on injector types is now bounded on `BridgeDispatch` instead of
  `BridgeHandler`
- **Breaking:** Injectors now use VMCALL (`GuestRequest`) instead of CPUID for
  guest-host bridge communication. Existing guest-side shellcode using CPUID
  must be updated
- **Breaking:** `VmiHandler::check_completion()` renamed to `VmiHandler::poll()`
- **Breaking:** `VmiEventResponse` redesigned from bitflags to an enum-based
  action model:
    - `VmiEventResponseFlags` removed, replaced by `VmiEventAction` enum
      with variants: `Continue`, `Deny`, `ReinjectInterrupt`, `Singlestep`,
      `FastSinglestep`, `Emulate`
    - `VmiEventResponse` fields changed: `flags` -> `action`
    - Builder methods `and_reinject_interrupt()`, `and_singlestep()`,
      `and_fast_singlestep()`, `and_emulate()` removed
    - `set_view()` / `and_set_view()` replaced by `with_view()`
    - `set_registers()` / `and_set_registers()` replaced by `with_registers()`
    - New: `VmiEventResponse::deny()` for suppressing CR/MSR write side effects
    - Singlestep now has one-shot semantics. The Xen driver automatically
      disables singlestep when a singlestep handler returns without
      `VmiEventAction::Singlestep`. Callers no longer need to manually
      toggle off.
    - `fast_singlestep` now requires a `View` parameter (the view to execute in)
- **Breaking:** GFN allocation API redesigned:
    - `allocate_gfn(gfn)` renamed to `allocate_gfn_at(gfn)` for allocating
      a specific GFN
    - `allocate_gfn()` now takes no parameters and returns
      `Result<Gfn, VmiError>`, with the driver choosing the GFN to allocate
    - `VmiCore::allocate_next_available_gfn()` removed (use `allocate_gfn()`
      instead)
- **Breaking:** `EventGuestRequest` renamed to `EventHypercall`;
  `EventReason::GuestRequest` renamed to `EventReason::Hypercall`;
  `EventMonitor::GuestRequest` renamed to `EventMonitor::Hypercall`;
  `as_guest_request()` renamed to `as_hypercall()`
- **Breaking:** `EventWriteControlRegister` renamed to `EventWriteCr`;
  `EventReason::WriteControlRegister` renamed to `EventReason::WriteCr`;
  `as_write_control_register()` renamed to `as_write_cr()`
- **Breaking:** `Pe` renamed to `PeHeader`
- **Breaking:** `PeExportDirectory` and `PeDebugDirectory` are now generic over
  `PeImage`

### Added

- `Msr` type with well-known MSR constants (SYSENTER_CS/ESP/EIP, EFER, STAR,
  LSTAR, CSTAR, FMASK, FS_BASE, GS_BASE, KERNEL_GS_BASE, TSC_AUX)
- MSR write monitoring: `EventMonitor::Msr`, `EventReason::WriteMsr`,
  `EventWriteMsr`, `as_write_msr()`

- `KernelInjectorHandler` / `UserInjectorHandler` type aliases
- Kernel-mode injection handler (`KernelMode`)
- `inject!` macro now supports `nt!` prefix for kernel symbol lookup

- `WindowsOs::idle_process()` - returns the idle process (PID 0)
- `WindowsOs::idle_thread()` - returns the idle thread for the current processor
- `WindowsOs::number_of_processors()` - returns the active processor count
- `WindowsOs::kprcb()` - returns the KPRCB for a given vCPU
- `WindowsThread::is_attached()` - checks if a thread is attached to a
  foreign process (via `_KTHREAD.ApcStateIndex`)
- `WindowsThread::saved_process()` - returns the thread's home process
  when attached to a foreign process (via `_KTHREAD.SavedApcState.Process`)
- `WindowsThread::teb()` and `WindowsThread::native_teb()` - return the thread's TEB
- `WindowsThread::trap_frame()` + `struct WindowsTrapFrame` - returns the thread's trap frame
- `WindowsProcess::native_peb()` - returns the process's native PEB (via `_EPROCESS.Peb`)
- `WindowsProcess::is_wow64()` - checks if the process is a WoW64 process (via `_EPROCESS.WoW64Process`)
- `WindowsModule::time_date_stamp()` - returns the `TimeDateStamp` from the
  kernel module's `_KLDR_DATA_TABLE_ENTRY`
- `WindowsUserModule` - Windows implementation backed by `_LDR_DATA_TABLE_ENTRY`
- `WindowsPebLdrData` - PEB loader data
- `WindowsPeb::ldr()` - returns the PEB loader data
- `WindowsKernelProcessorBlock` - per-processor KPRCB
- `WindowsExceptionVector` trait for Windows-specific exception vectors (APC, DPC)
- `WindowsInterrupt` trait for creating Windows-specific interrupts
- `WindowsPageTableEntry` trait made public
- `ptm::arch` module made public, exposing `ArchAdapter`
- `KiDeliverApc` kernel symbol
- `WindowsTeb::tls_slot()` for reading thread-local storage slots
- WoW64 TLS slot constants (`WOW64_TLS_CPURESERVED`, ...)
- `FromWindowsObject` trait for typed conversion from `WindowsObject`
- `WindowsProcess::lookup_object()` method for typed handle lookup
- `WindowsThreadState` enum representing `KTHREAD_STATE` scheduling states
- `WindowsThread::state()` - returns the thread's scheduling state (via `_KTHREAD.State`)
- `BreakpointManager::handle_ptm_events()` - batch processing for page table monitor events
- `GpRegisters` marker trait in `vmi-core` for general-purpose register sets
- `VmiOsUserModule` trait in `vmi-core` for enumerating user-mode modules
- Windows CONTEXT structure definitions (`CONTEXT_X86`, `CONTEXT_AMD64`)
- `WindowsContext` trait - accessor for general-purpose registers, RIP, flags, segments from a `CONTEXT`
- `WindowsSpecialRegisters` trait - accessor for control/debug registers and descriptor tables from `KSPECIAL_REGISTERS`
- `WindowsRegistersAdapter` trait - writes `WindowsContext`/`WindowsSpecialRegisters` into VMI Registers

- `PeImage` trait - abstracts PE data access
- `PeFile` - file-backed PE parser with section-based RVA-to-file-offset translation
- `PeExceptionDirectory` - parses .pdata RUNTIME_FUNCTION entries

- `unwind` module with x64 stack unwinder

### Fixed

## [0.4.0] - 2025-08-15

### Changed

- Updated lifetime annotations to avoid warnings on Rust 1.89
- `RecipeContext` and `RecipeExecutor` now operate over `VmiState` instead of
  `VmiContext`

### Added

- WindowsOs::object_type - to return `WindowsObjectType` from
  `WindowsObjectTypeKind`

### Fixed

- Fixed handling of large page table entries in `PageTableMonitor`
- Fixed finding of `ntoskrnl` for recent Windows versions

## [0.3.0] - 2025-03-13

### Changed

- Switched to rust edition 2024 and MSRV 1.85
- These functions now return Option:
    - WindowsProcess::peb()
    - WindowsProcess::handle_table()
- InjectorHandler::inject() now returns an Result&lt;InjectorResultCode, BridgePacket&gt; instead of ()

### Added

- WindowsHandleTable::iter() now returns HandleTableEntryIterator

### Fixed

## [0.2.0] - 2025-02-04

### Changed

- VmiOs refactored from the ground up
    - Each OS component is now a separate struct
    - Common OS components are now traits (VmiOsProcess, VmiOsThread, ...)
- VmiHandler::finished() is renamed to VmiHandler::check_completion(),
  which now returns an Option&lt;Output&gt; instead of a bool

### Added

- New drivers for offline analysis
    - VmiDriverKdmp, VmiDriverXenCoreDump
- Implemented handling of PFN changes in the PageTableMonitor
- Added Output type to the VmiHandler
- vmi_core::os::OsModule + VmiOs::modules() to get the list of loaded modules

### Fixed

- Return PageIn event when connecting an intermediate PTE
