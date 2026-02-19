# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `WindowsThread::attached_process()` renamed to
  `WindowsThread::current_process()`

### Added

- `WindowsThread::is_attached()` - checks if a thread is attached to a
  foreign process (via `_KTHREAD.ApcStateIndex`)
- `WindowsThread::saved_process()` - returns the thread's home process
  when attached to a foreign process (via `_KTHREAD.SavedApcState.Process`)
- `WindowsThread::teb()` and `WindowsThread::native_teb()` - return the thread's TEB
- `WindowsThread::trap_frame()` + `struct WindowsTrapFrame` - returns the thread's trap frame
- `WindowsProcess::native_peb()` - returns the process's native PEB (via `_EPROCESS.Peb`)
- `WindowsProcess::is_wow64()` - checks if the process is a WoW64 process (via `_EPROCESS.WoW64Process`)
- `WindowsExceptionVector` trait for Windows-specific exception vectors (APC, DPC)
- `WindowsInterrupt` trait for creating Windows-specific interrupts
- `WindowsPageTableEntry` trait made public
- `KiDeliverApc` kernel symbol
- `WindowsTeb::tls_slot()` for reading thread-local storage slots
- WoW64 TLS slot constants (`WOW64_TLS_CPURESERVED`, ...)

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
