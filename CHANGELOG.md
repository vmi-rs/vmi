# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to **_will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 0.3.0_**.

## [Unreleased]

### Changed

### Added

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
