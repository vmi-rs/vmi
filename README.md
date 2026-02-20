[![Crates.io](https://img.shields.io/crates/v/vmi.svg)](https://crates.io/crates/vmi)
[![Downloads](https://img.shields.io/crates/d/vmi.svg)](https://crates.io/crates/vmi)
[![Docs](https://docs.rs/vmi/badge.svg)](https://docs.rs/vmi/latest/vmi/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/vmi-rs/vmi/blob/master/LICENSE)

# Virtual Machine Introspection

A comprehensive framework for Virtual Machine Introspection (VMI)
implemented in Rust, providing safe abstractions for analyzing and
manipulating virtual machine state from the outside.

# Table of Contents

- [Introduction](#introduction)
  - [Motivation](#motivation)
  - [The Semantic Gap](#the-semantic-gap)
  - [The VMI Landscape](#the-vmi-landscape)
  - [Disclaimer](#disclaimer)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Examples](#examples)
- [Core Concepts](#core-concepts)
  - [Address Types](#address-types)
  - [Address Contexts](#address-contexts)
- [Architecture](#architecture)
  - [Core Components](#core-components)
    - [Relationship between `VmiCore`, `VmiSession`, `VmiState` and `VmiContext`](#relationship-between-vmicore-vmisession-vmistate-and-vmicontext)
    - [OS-Specific Operations](#os-specific-operations)
    - [Implicit vs. Explicit Registers](#implicit-vs-explicit-registers)
  - [Event Handling](#event-handling)
  - [Utilities](#utilities)
- [ISR](#isr)
- [Current Limitations](#current-limitations)
- [See Also](#see-also)
- [License](#license)

# Introduction

VMI is a powerful technique for analyzing and manipulating virtual
machines from the outside. It is used in a variety of security
applications, including malware analysis, intrusion detection,
and digital forensics.

## Motivation

However, VMI is complex and error-prone, requiring low-level
interactions with the virtual machine. This framework aims to
simplify VMI by providing a high-level, type-safe API for common
operations, such as memory access, CPU register manipulation,
and OS-specific introspection.

The framework is designed to be modular and extensible, supporting
multiple CPU architectures, hypervisors, and operating systems.
It includes built-in support for AMD64 architecture, Xen hypervisor,
and Windows and Linux operating systems.

## The Semantic Gap

VMI involves interacting with a virtual machine at a very low level,
often requiring direct manipulation of memory and registers.
A common challenge is the *semantic gap* between these low-level
operations (e.g., reading memory) and the higher-level understanding
of the guest OS needed for meaningful analysis (e.g., enumerating
processes and analyzing their modules).

This framework addresses this gap through a layered architecture,
from raw hypervisor interactions, through OS-specific abstractions
like [`WindowsOs`] and [`LinuxOs`], to integration with the [ISR]
library, providing version-agnostic access to OS internals.

## The VMI Landscape

Let's be honest, VMI doesn't get the love it deserves. While incredibly
useful, it's not as widely supported as it should be. Xen is currently
the champion of VMI support among major hypervisors. Other hypervisors,
like VMware, Hyper-V, and VirtualBox, haven't quite jumped on the VMI
bandwagon yet.

There have been attempts to bring VMI to other platforms, such as the
[KVM-VMI] project. Unfortunately, these efforts haven't been merged into
the mainline and the project hasn't been updated in a while.

This project aims to shine a spotlight on VMI and encourage wider adoption.
While currently focused on Xen, the framework is designed to be
hypervisor-agnostic. We're optimistically waiting for the day when other
hypervisors join the VMI party!

## Disclaimer

This project is still in its early stages and under active development.
Expect breaking changes and rough edges. Feedback, bug reports, and
contributions are welcome!

# Features

- Type-safe memory access through [`Va`], [`Pa`], and [`Gfn`] types.

- Configurable caching mechanisms for [physical page lookups] and
  [Virtual-to-Physical address translations] to improve performance.

- [ISR] library for version-agnostic OS introspection.

- Sophisticated error handling, including robust page-fault handling.

- Modular architecture allowing for seamless integration of new hypervisor
  drivers, CPU architectures, and OS support.

- Batteries included:
    - Built-in OS support with [`WindowsOs`] and [`LinuxOs`].
    - Powerful utilities like [`BreakpointManager`], [`PageTableMonitor`],
      and [`InjectorHandler`].

# Quick Start

Add the following to your `Cargo.toml`:

```toml
[dependencies]
vmi = "0.2"
```

Basic usage example:

```rust,ignore
use isr::{cache::JsonCodec, IsrCache};
use vmi::{
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{windows::WindowsOs, VmiOsProcess as _},
    VcpuId, VmiCore, VmiSession,
};
use xen::XenDomainId;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(XenDomainId(1))?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        // Pause the vCPU to get consistent state.
        let _pause_guard = core.pause_guard()?;

        // Get the register state for the first vCPU.
        let registers = core.registers(VcpuId(0))?;

        // On AMD64 architecture, the kernel is usually found using the
        // `MSR_LSTAR` register, which contains the address of the system call
        // handler. This register is set by the operating system during boot
        // and is left unchanged (unless some rootkits are involved).
        //
        // Therefore, we can take an arbitrary registers at any point in time
        // (as long as the OS has booted and the page tables are set up) and
        // use them to find the kernel.
        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    // Pause the VM again to get consistent state.
    let _pause_guard = session.pause_guard()?;

    // Create a new `VmiState` with the current register.
    let registers = session.registers(VcpuId(0))?;
    let vmi = session.with_registers(&registers);

    // Get the list of processes and print them.
    for process in vmi.os().processes()? {
        let process = process?;

        println!(
            "{} [{}] {} (root @ {})",
            process.object()?,
            process.id()?,
            process.name()?,
            process.translation_root()?
        );
    }

    Ok(())
}
```

# Installation

But first, you need to install the prerequisites.

The framework has been tested on Ubuntu 22.04 and Xen 4.20.
Note that Xen 4.20 is the minimum version required to use the
framework, and it is the current version (at the time of writing).

Unfortunately, Xen 4.20 is not available in the official Ubuntu
repositories, so it must be built from source.

This guide assumes you have a fresh Ubuntu 22.04 installation.

> *Sorry, the guide is still under construction. Please check back later.*

# Examples

The framework includes several examples demonstrating various VMI
capabilities, from basic operations to more complex scenarios.

- **[`basic.rs`]**

  Demonstrates fundamental VMI operations like retrieving the Interrupt
  Descriptor Table (IDT) for each virtual CPU.

- **[`basic-process-list.rs`]**

  Shows how to retrieve and display a list of running processes in the
  guest VM.

- **[`windows-breakpoint-manager.rs`]**

  Illustrates the usage of the [`BreakpointManager`] and
  [`PageTableMonitor`] to set and manage breakpoints on Windows systems.

- **[`windows-dump.rs`]**

  Demonstrates how to use the VMI library to analyze a Windows kernel dump file.

- **[`windows-recipe-messagebox.rs`]**

  A simple example of code injection using a recipe to display a message
  box in the guest.

- **[`windows-recipe-writefile.rs`]**

  Demonstrates injecting code that writes data to a file in the guest.

- **[`windows-recipe-writefile-advanced.rs`]**

  A more complex example showing how to write to a file in chunks and
  handle potential errors during injection.

# Core Concepts

## Address Types

The framework uses distinct types to represent different kinds of memory
addresses within the guest:

- [`Va`]: Guest Virtual Address.
- [`Pa`]: Guest Physical Address.
- [`Gfn`]: Guest Frame Number.

These types provide type safety and support arithmetic operations,
comparisons and formatting.

Example:

```rust,ignore
use vmi::{
    arch::amd64::{Amd64, Cr3},
    Architecture as _, Gfn, Pa, Va,
};

let gfn = Gfn(0x1aa);
let pa = Amd64::pa_from_gfn(gfn);
assert_eq!(pa, Pa(0x1aa000));

let pa = Pa(0x1aa000);
let gfn = Amd64::gfn_from_pa(pa);
assert_eq!(gfn, Gfn(0x1aa));

let cr3 = Cr3(0x1aa000);
let va = Va(0xfffff804590c8980);
let pa = Amd64::translate_address(vmi, va, cr3.into())?;
```

## Address Contexts

Additionally, two key structures manage address translation:

- [`AddressContext`]: Combines a virtual address ([`Va`]) and
  a translation root ([`Pa`], typically the `CR3` register) to provide
  a complete context for virtual-to-physical address translation.

  This structure is used as input for address translation and memory access
  functions.

  Example:

    ```rust,ignore
    let cr3 = Cr3(0x1aa000);
    let va = Va(0xfffff804590c8980);
    let address_context = AddressContext::new(va, cr3);
    ```

- [`AccessContext`]: Defines the context for memory operations,
  encapsulating the target address and the [`TranslationMechanism`].
  This allows for both direct physical access and paging-based translation.

  Example:

    ```rust,ignore
    // Direct physical memory access:
    let access_context = AccessContext::direct(Pa(0x1fc7980));
    assert!(matches!(
        access_context.mechanism,
        TranslationMechanism::Direct
    ));

    // Paging-based translation:
    let cr3 = Cr3(0x1aa000);
    let va = Va(0xfffff804590c8980);
    let access_context = AccessContext::paging(va, cr3);
    assert!(matches!(
        access_context.mechanism,
        TranslationMechanism::Paging {
            root: Some(Pa(0x1aa000))
        }
    ));
    ```

# Architecture

The framework is designed to be modular and extensible, supporting multiple
CPU architectures, hypervisors, and operating systems.

## Core Components

The core components of the framework are:

- [`Architecture`]: A trait abstracting CPU architecture-specific logic,
  such as register definitions and address translation.

  Currently, the framework includes an [`Amd64`] implementation.

- [`VmiDriver`]: A trait defining the interface for interacting with the
  hypervisor. This allows the framework to support multiple hypervisors.

  Currently, the framework includes a [`VmiXenDriver`] for Xen.

- [`VmiCore`]: Provides raw VMI operations, interacting directly with
  the [`VmiDriver`] and leveraging the [`Architecture`]. It handles
  memory access, address translation, and register manipulation,
  but has no inherent OS awareness.

  Importantly, `VmiCore` does *not* store register state, requiring it
  to be explicitly provided for operations that depend on it.

- [`VmiOs`]: A trait defining OS-specific introspection operations.
  Implementations of this trait, such as [`WindowsOs`] and [`LinuxOs`],
  provide higher-level functions for interacting with the guest OS,
  bridging the semantic gap between raw memory access and meaningful
  OS analysis.

- [`VmiSession`]: Combines a [`VmiCore`] with a [`VmiOs`] implementation
  to provide OS-aware operations. This enables high-level introspection
  tasks, but - like `VmiCore` - `VmiSession` does not store register state.

- [`VmiState`]: Represents a state of the virtual machine at a given moment,
  combining [`VmiSession`] with [`Architecture::Registers`].
  This allows for consistent access to memory, registers, and OS-level
  abstractions without requiring explicit register state management for
  every operation.

- [`VmiContext`]: Represents a point-in-time state of the virtual CPU
  during event handling, combining [`VmiState`] with a [`VmiEvent`].

- [`VmiError`]: Represents errors that can occur during VMI operations,
  including translation faults ([`Translation`]).

### Relationship between `VmiCore`, `VmiSession`, `VmiState` and `VmiContext`

Each of these structures can be implicitly dereferenced down the hierarchy.
This means that:

- `VmiContext` implements [`Deref`] to `VmiState`
  - which in turn implements `Deref` to `VmiSession`
    - which in turn implements `Deref` to `VmiCore`.

This design enables convenient access to lower-level functionality:

- Access `VmiCore` methods directly from a `VmiSession`, `VmiState` or
  `VmiContext` without explicit dereferencing.

- Pass a `&VmiContext` to functions expecting a `&VmiState`, `&VmiSession`
  or `&VmiCore`.

#### OS-Specific Operations

> *Consult the [`os`] module documentation for more information
> and examples.*

Both `VmiState` and `VmiContext` provide access to OS-specific
functionality through the [`os()`] method. This method returns a structure
implementing the [`VmiOs`] trait methods, as well as any additional
OS-specific operations.

#### Implicit vs. Explicit Registers

As pointed out above, `VmiCore` and `VmiSession` do *not* store register
state. This means that functions requiring register information (e.g.,
for address translation or OS-specific operations) must be explicitly
provided with the register state.

`VmiState` and `VmiContext`, on the other hand, *do* hold the register
state. This difference has important implications for how you interact with
these components:

- With `VmiCore` and `VmiSession`, you must explicitly provide
  the translation root (e.g., `CR3`) when performing memory operations:

  ```rust,ignore
  let va = Va(0xfffff804590c8980);

  // let vmi: &VmiSession = ...;
  let registers = vmi.registers(VcpuId(0))?;
  let value = vmi.read_u64((va, registers.cr3.into()))?; // Explicitly pass the translation root (CR3)
  ```

- With `VmiState` and `VmiContext`, register state is managed internally:

  ```rust,ignore
  // let vmi: &VmiContext = ...;
  let value = vmi.read_u64(va)?; // No need to pass the translation root
  ```

This extends to OS-specific operations as well.

- `VmiSession` requires explicit register state:

```rust,ignore
// let session: &VmiSession = ...;
let registers = session.registers(VcpuId(0))?;
let vmi = session.with_registers(&registers); // Create a new VmiState
let process = vmi.os().current_process()?;
let process_id = process.id()?;
```

- `VmiState` and `VmiContext` simplifies this by providing register state
  implicitly:

```rust,ignore
// let vmi: &VmiContext = ...;
let process = vmi.os().current_process()?;
let process_id = process.id()?;
```

## Event Handling

The event system allows responding to guest activities:

- [`VmiEvent`]: Represents various guest events (memory access, interrupts,
  register changes). Carries event-specific data and register state at the
  time of the event.

- [`VmiHandler`]: A trait for implementing event handlers.
  The [`handle_event`] method defines how your application
  responds to specific guest events.

- [`VmiEventResponse`]: Controls guest execution after an event.
  Options include continuing, single-stepping and modifying registers.

## Utilities

Several utility components are provided to simplify common VMI tasks:

- [`PageTableMonitor`]: Tracks page table modifications, generating
  [`PageIn`]/[`PageOut`] events.

- [`BreakpointManager`]: Manages software breakpoints, handling
  [`PageIn`]/[`PageOut`] events.

- [`InjectorHandler`]: Provides a high-level interface for code injection,
  handling thread hijacking and argument marshalling.

- [`Interceptor`]: Low-level breakpoint management.
  Use [`BreakpointManager`] instead whenever possible.

# ISR

> *Consult the [`isr`] crate documentation for more information
> and examples.*

The framework leverages Intermediate Symbol Representation (ISR) for
version-agnostic OS introspection. It avoids the need for hardcoding
offsets and makes the code adaptable to different OS versions.

- [`IsrCache`]: Manages symbol files (PDB for Windows, DWARF for Linux).
  Automatically downloads and caches PDBs based on CodeView information
  (Windows) or kernel version banner (Linux).

- [`symbols!`] macro: Defines symbols for lookup.

  Example:

    ```rust,ignore
    use isr::macros::symbols;

    symbols! {
        pub struct Symbols {
            NtCreateFile: u64,
            PsActiveProcessHead: u64,
        }
    }
    ```

- [`offsets!`] macro: Defines structure offsets.

  Example:

    ```rust,ignore
    use isr::macros::{offsets, Field};

    offsets! {
        pub struct Offsets {
            struct _EPROCESS {
                UniqueProcessId: Field,
                ActiveProcessLinks: Field,
            }
        }
    }
    ```

# Current Limitations

- **Architecture Support**: Currently only AMD64 is supported.
  No x86 (32-bit) support, including 32-bit paging or code injection into
  32-bit processes. 5-level paging is also not supported.

- **Hypervisor Support**: Only Xen is supported through [`VmiXenDriver`].

- **Operating System Support**:
    - **Windows**: Good support for Windows 7 and later.
    - **Linux**: Limited functionality. Many features are still under
      development.
    - No other operating systems are currently supported.

# See Also

If you're new to VMI or looking for more information, check out these
amazing projects and resources:

- **[libvmi]**: A popular VMI library written in C.
- **[hvmi]**: Hypervisor Memory Introspection from Bitdefender.
- **[drakvuf]**: Dynamic malware analysis system using VMI.
- **[KVM-VMI]**: A project to bring VMI to the KVM hypervisor.

# License

This project is licensed under the MIT license.

[physical page lookups]: crate::VmiCore::with_gfn_cache
[Virtual-to-Physical address translations]: crate::VmiCore::with_v2p_cache



[KVM-VMI]: https://github.com/KVM-VMI/kvm-vmi

[`basic-process-list.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic-process-list.rs
[`windows-breakpoint-manager.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-breakpoint-manager.rs
[`windows-dump.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-dump.rs
[`windows-recipe-messagebox.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-messagebox.rs
[`windows-recipe-writefile.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile.rs
[`windows-recipe-writefile-advanced.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile-advanced.rs

[`AccessContext`]: https://docs.rs/vmi/latest/vmi/struct.AccessContext.html
[`AddressContext`]: https://docs.rs/vmi/latest/vmi/struct.AddressContext.html
[`Architecture`]: https://docs.rs/vmi/latest/vmi/trait.Architecture.html
[`Gfn`]: https://docs.rs/vmi/latest/vmi/struct.Gfn.html
[`Pa`]: https://docs.rs/vmi/latest/vmi/latest/vmi/struct.Pa.html
[`Translation`]: https://docs.rs/vmi/0.1.1/vmi/enum.VmiError.html#variant.Translation
[`TranslationMechanism`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html
[`Va`]: https://docs.rs/vmi/latest/vmi/latest/vmi/struct.Va.html
[`VmiContext`]: https://docs.rs/vmi/latest/vmi/struct.VmiContext.html
[`VmiCore`]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html
[`VmiDriver`]: https://docs.rs/vmi/latest/vmi/trait.VmiDriver.html
[`VmiError`]: https://docs.rs/vmi/latest/vmi/enum.VmiError.html
[`VmiEvent`]: https://docs.rs/vmi/latest/vmi/struct.VmiEvent.html
[`VmiEventResponse`]: https://docs.rs/vmi/latest/vmi/struct.VmiEventResponse.html
[`VmiHandler`]: https://docs.rs/vmi/latest/vmi/trait.VmiHandler.html
[`VmiOs`]: https://docs.rs/vmi/latest/vmi/trait.VmiOs.html
[`VmiSession`]: https://docs.rs/vmi/latest/vmi/struct.VmiSession.html
[`VmiState`]: https://docs.rs/vmi/latest/vmi/struct.VmiState.html

[`Amd64`]: https://docs.rs/vmi/latest/vmi/arch/amd64/struct.Amd64.html
[`VmiXenDriver`]: https://docs.rs/vmi/latest/vmi/driver/xen/struct.VmiXenDriver.html
[`LinuxOs`]: https://docs.rs/vmi/latest/vmi/os/linux/struct.LinuxOs.html
[`WindowsOs`]: https://docs.rs/vmi/latest/vmi/os/windows/struct.WindowsOs.html
[`Direct`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Direct
[`Paging`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Paging
[`root`]: https://docs.rs/vmi/latest/vmi/enum.TranslationMechanism.html#variant.Paging.field.root
[`BreakpointManager`]: https://docs.rs/vmi/latest/vmi/utils/bpm/struct.BreakpointManager.html
[`InjectorHandler`]: https://docs.rs/vmi/latest/vmi/utils/injector/struct.InjectorHandler.html
[`Interceptor`]: https://docs.rs/vmi/latest/vmi/utils/interceptor/struct.Interceptor.html
[`PageTableMonitor`]: https://docs.rs/vmi/latest/vmi/utils/ptm/struct.PageTableMonitor.html
[`PageIn`]: https://docs.rs/vmi/latest/vmi/utils/ptm/enum.PageTableMonitorEvent.html#variant.PageIn
[`PageOut`]: https://docs.rs/vmi/latest/vmi/utils/ptm/enum.PageTableMonitorEvent.html#variant.PageOut
[`handle_event`]: https://docs.rs/vmi/latest/vmi/trait.VmiHandler.html#tymethod.handle_event
[`os()`]: https://docs.rs/vmi/latest/vmi/struct.VmiState.html#method.os
[`os`]: https://docs.rs/vmi/latest/vmi/os/index.html
[physical page lookups]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html#method.with_gfn_cache
[Virtual-to-Physical address translations]: https://docs.rs/vmi/latest/vmi/struct.VmiCore.html#method.with_v2p_cache

[`Deref`]: https://doc.rust-lang.org/std/ops/trait.Deref.html

[ISR]: https://docs.rs/isr/latest/isr/index.html
[`isr`]: https://docs.rs/isr/latest/isr/index.html
[`IsrCache`]: https://docs.rs/isr/latest/isr/cache/struct.IsrCache.html
[`offsets!`]: https://docs.rs/isr/latest/isr/macros/macro.offsets.html
[`symbols!`]: https://docs.rs/isr/latest/isr/macros/macro.symbols.html

[KVM-VMI]: https://github.com/KVM-VMI/kvm-vmi
[libvmi]: https://github.com/libvmi/libvmi
[hvmi]: https://github.com/bitdefender/hvmi
[drakvuf]: https://github.com/tklengyel/drakvuf

[`basic.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic.rs
[`basic-process-list.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/basic-process-list.rs
[`windows-breakpoint-manager.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-breakpoint-manager.rs
[`windows-dump.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-dump.rs
[`windows-recipe-messagebox.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-messagebox.rs
[`windows-recipe-writefile.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile.rs
[`windows-recipe-writefile-advanced.rs`]: https://github.com/vmi-rs/vmi/blob/master/examples/windows-recipe-writefile-advanced.rs
