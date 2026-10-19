<!-- readme start -->
VMI driver for QEMU migration streams.

Reads the state of a VM from a migration stream that the QEMU `migrate`
command wrote to a file, such as with `migrate "exec:cat > vm.mig"`. The
driver maps the file into memory. A stream that went through a compressor
must be decompressed first.

The stream must end with the JSON VM description, which QEMU writes unless
the machine property `suppress-vmdesc` is set. The description names each
field of each device section and gives its size, so the driver can walk the
device sections of any machine.

# Memory

The RAM section holds the pages of each RAM block, addressed by block name
and offset. The machine type decides where the blocks appear in guest
physical memory. `ArchAdapter::ram_ranges` maps the main RAM block of each
supported machine type:

- `Amd64` reads the `pc-i440fx-*` and `pc-q35-*` machines of
  qemu-system-x86_64 and qemu-system-i386. Their `pc.ram` block starts at
  address 0 and continues at 4 GiB when it does not fit below the PCI hole.
- `Arm64` reads the `virt` machine, with `mach-virt.ram` at 1 GiB, and the
  `vmapple` machine, with `mach-vmapple.ram` at `0x70000000`.

Other RAM blocks, such as firmware, option ROMs and video memory, cannot be
read. The last record of a page decides its content. A page that the stream
does not hold reads as zero, as it does in a VM that loads the stream.

# Registers

QEMU saves each vCPU as a device section named `cpu`, with the vCPU index as
the instance id. `ArchAdapter::registers` reads the registers from it. For
ARM64, the system registers come from the `cpreg` list, which QEMU fills
from KVM or from TCG.

# Notes

The driver rejects streams that it would read wrong. These are streams of
postcopy or COLO migration, streams with the `x-ignore-shared` or
`mapped-ram` capability, and RAM sections with XBZRLE, multifd or RDMA
records.

For the x86 machines, the driver assumes the default of the
`max-ram-below-4g` machine property, which the stream does not record.
<!-- readme end -->
