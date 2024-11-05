# Architecture abstraction

This module provides traits and structures for abstracting CPU architectures
in the context of Virtual Machine Introspection (VMI). It allows for
architecture-independent VMI operations while still providing access to
architecture-specific details when needed.

## Features

- Abstract representation of memory layouts and address translation.
- Architecture-independent access to CPU registers.
- Support for architecture-specific interrupt and event handling.
- Flexible design allowing for easy addition of new architectures.

## Key Components

- [`Architecture`]: The core trait for implementing architecture-specific operations.
- [`Registers`]: Trait for accessing and manipulating CPU registers.
- [`EventReason`]: Architecture-specific reasons for VMI events.
