<!-- readme start -->
# macOS OS-specific VMI operations

This crate provides functionality for introspecting macOS virtual
machines on Apple silicon, working in conjunction with the `vmi-core`
crate. It navigates the structures of the XNU kernel to enumerate
processes, threads, memory regions, open files and kernel extensions.

## Features

- Locating the kernel collection and the kernel image in memory
- Per-segment relocation of profile symbols
- Process and thread introspection
- Memory region enumeration with mapped file paths
- Open file enumeration
- Kernel extension and dyld image enumeration
- Mach-O image parsing

## Kernel layout

The kernel of macOS on Apple silicon is part of a kernel collection, an
`MH_FILESET` Mach-O image that bundles the kernel with its extensions.
Building the collection rearranges the segments of the kernel, and the
whole collection is slid at boot. The distance between a segment in
memory and the same segment in the Kernel Debug Kit therefore differs
from segment to segment. [`MacOs::find_kernel`] reads the segment table
of the kernel in memory, and [`MacOs::new`] relocates every profile
symbol by the segment that contains it.

Kernel pointers may carry pointer authentication codes, which this crate
strips from every pointer it reads.

## Address spaces

Kernel addresses translate through `TTBR1_EL1` of the registers in the
[`VmiState`]. The user half of a process translates through the table at
`task.map->pmap->ttep`, which the [`translation_root`] of a process
returns.

## Examples

```rust,ignore
let registers = core.registers(VcpuId(0))?;
let kernel_info = MacOs::find_kernel(core, &registers)?.expect("kernel information");

let isr = IsrCache::new("cache")?;
let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
let profile = entry.profile()?;

let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
let session = VmiSession::new(core, &os);
let vmi = session.with_registers(&registers);

for process in vmi.os().processes()? {
    let process = process?;
    println!("{} {}", process.id()?, process.name()?);
}
```
<!-- readme end -->
