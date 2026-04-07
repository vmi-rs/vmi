# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
