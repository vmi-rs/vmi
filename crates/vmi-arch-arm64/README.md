<!-- readme start -->
ARM64 (AArch64) architecture definitions.

[`Arm64`] is generic over a [`PagingGeometry`] that fixes the translation
granule and the VA size of the guest at compile time:

- [`Granule4KVa48`]: 4KB pages, 48-bit VA, walk from L0.
- [`Granule16KVa47`]: 16KB pages, 47-bit VA, walk from L1.

The geometry must match the guest's `TCR_EL1`, which
[`PagingGeometry::matches_tcr`] verifies. Bit 55 of a virtual address
selects `TTBR1_EL1` (set) or `TTBR0_EL1` (clear) as the translation root.
Pointers read from guest memory may carry pointer authentication codes or
top-byte tags, which [`Arm64::canonical_address`] strips.
<!-- readme end -->
