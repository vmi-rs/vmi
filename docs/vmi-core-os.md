# OS introspection

This module provides traits and structures for OS-aware introspection of
virtual machines. It allows for high-level analysis and manipulation of
guest operating systems, abstracting away many of the low-level details of
different OS implementations.

## Overview

This module is at the heart of OS introspection. It defines several traits that
allow users to implement OS-specific logic while offering a consistent interface
to:
- Enumerate and inspect processes and threads.
- Analyze memory regions, including both private and file-backed (mapped) regions.
- Inspect kernel modules and executable images.
- Safely read structured data from guest memory.

Additionally, a dummy implementation ([`NoOS`]) is provided as a placeholder for
cases where an OS-specific implementation is not available or required.

## Key Components

### Core OS Trait

- **[`VmiOs`]**
  This is the central trait for OS introspection. It defines associated types
  for the following:
  - **Process**: Represented via the [`VmiOsProcess`] trait.
  - **Thread**: Represented via the [`VmiOsThread`] trait.
  - **Executable Image**: Represented via the [`VmiOsImage`] trait.
  - **Kernel Module**: Represented via the [`VmiOsModule`] trait.
  - **Memory Region**: Represented via the [`VmiOsRegion`] trait.
  - **Mapped Region**: Represented via the [`VmiOsMapped`] trait.

  In addition to these, it provides methods to retrieve critical OS-specific
  information, such as the kernel image base, and whether Kernel Page Table
  Isolation (KPTI) is enabled.

### Process and Thread Introspection

- **[`VmiOsProcess`]**

  Provides an interface for inspecting guest processes. It offers methods to
  obtain the process ID, name, parent process ID, memory translation roots,
  and memory regions.

- **[`ProcessObject`] and [`ProcessId`]**

  Strong types that represent underlying OS process structures such as
  `_EPROCESS` on Windows or `task_struct` on Linux. This design minimizes
  mistakes by ensuring that process objects are used correctly within the API.

- **[`VmiOsThread`]**

  Offers methods to inspect thread objects, including obtaining the
  thread ID and an associated thread object.

- **[`ThreadObject`] and [`ThreadId`]**

  Similar to process types, these are strong types representing underlying
  OS thread structures (e.g., `_ETHREAD` on Windows). Their strong typing helps
  prevent mix-ups with other addresses or identifiers.

### Memory Region and Mapped Region Introspection

- **[`VmiOsRegion`]**

  Defines the interface for memory region introspection. Methods include
  obtaining the start and end addresses, memory protection details, and the
  kind of region (private or mapped).

- **[`VmiOsRegionKind`]**

  An enum that distinguishes between private and mapped memory regions.

- **[`VmiOsMapped`]**

  Specializes in introspecting memory regions that are file-backed. It provides
  a method to retrieve the backing file’s path.

### Kernel Modules and Executable Images

- **[`VmiOsModule`]**

  Offers an abstraction for kernel module introspection, providing methods to
  access a module’s base address, size, and name.

- **[`VmiOsImage`]**

  Defines methods for executable images (binaries, shared libraries) to retrieve
  the base address, target architecture, and exported symbols.

### Additional Components

- **[`StructReader`]**

  A utility for safely reading structured data (such as C structs) from guest
  memory.

- **[`NoOS`]**

  A dummy implementation of the `VmiOs` trait for cases where no specific OS
  introspection is provided. It serves as a placeholder or for testing purposes.
