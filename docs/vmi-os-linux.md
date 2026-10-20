<!-- readme start -->
# Linux OS-specific VMI operations

This crate provides functionality for introspecting Linux-based virtual
machines, working in conjunction with the `vmi-core` crate. It reads the
symbols and structure offsets of the guest's kernel from an isr profile.

## Supported kernels

Linux 6.8 and later on AMD64. The kernel changed where it keeps the pointer
to the current task in 6.15, and the crate picks the layout from the symbols
in the profile, not from the version string.

Under page table isolation (KPTI), a vCPU in user mode runs on page tables
that map almost none of the kernel. The crate then reads the kernel through
the kernel page tables of the same process. Its methods therefore work with
any vCPU's registers.

## Features

- Kernel discovery: the banner, the KASLR offset, the kernel image base and
  KPTI
- Processes and threads, including the current process and thread
- Memory regions of a process, with the paths of mapped files
- Kernel modules
- Syscall and function arguments and the return value

Images, user-mode modules and the last error are not supported yet. Their
methods return `VmiError::NotSupported`.

The example `linux-process-list` of the `vmi` crate lists the processes,
threads, memory regions and kernel modules of a guest.

## Safety Considerations

Many operations in this crate require pausing the VM to ensure consistency.
Always pause the VM when performing operations that could be affected by
concurrent changes in the guest OS. Make sure that the profile matches the
guest's kernel, as structure layouts change between kernel builds. Handle
errors appropriately, as VMI operations can fail for many reasons, such as
invalid memory access or a profile of another kernel.

## Examples

```rust,ignore
let _guard = vmi.pause_guard()?;
// Perform introspection operations here
// VM automatically resumes when `_guard` goes out of scope
```

Always consider the potential for race conditions and ensure you're
working with a consistent state of the guest OS.
<!-- readme end -->
