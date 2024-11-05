use super::{SegmentAccess, Selector};

/// A segment descriptor is a data structure in a GDT or LDT that provides the
/// processor with the size and location of a segment, as well as access control
/// and status information. Segment descriptors are typically created by
/// compilers, linkers, loaders, or the operating system or executive, but not
/// application programs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SegmentDescriptor {
    /// Defines the location of byte 0 of the segment within the 4-GByte linear
    /// address space. Segment base addresses should be aligned to 16-byte
    /// boundaries. Although 16-byte alignment is not required,
    /// this alignment allows programs to maximize performance by aligning code
    /// and data on 16-byte boundaries.
    pub base: u64,

    /// Specifies the size of the segment. The processor interprets the segment
    /// limit in one of two ways, depending on the setting of the G
    /// (granularity) flag:
    ///
    /// - If the granularity flag is clear, the segment size can range from 1
    ///   byte to 1 MByte, in byte increments.
    ///
    /// - If the granularity flag is set, the segment size can range from 4
    ///   KBytes to 4 GBytes, in 4-KByte increments.
    ///
    /// The processor uses the segment limit in two different ways, depending on
    /// whether the segment is an expand-up or an expand-down segment. For
    /// expand-up segments, the offset in a logical address can range from 0
    /// to the segment limit. Offsets greater than the segment limit
    /// generate general-protection exceptions (#GP, for all segments other than
    /// SS) or stack-fault exceptions (#SS for the SS segment). For
    /// expand-down segments, the segment limit has the reverse
    /// function; the offset can range from the segment limit plus 1 to
    /// FFFFFFFFH or FFFFH, depending on the setting of the B flag. Offsets
    /// less than or equal to the segment limit generate general-protection
    /// exceptions or stack-fault exceptions. Decreasing the value in the
    /// segment limit field for an expanddown segment allocates new memory
    /// at the bottom of the segment's address space, rather than at
    /// the top. IA-32 architecture stacks always grow downwards, making this
    /// mechanism convenient for expandable stacks.
    pub limit: u32,

    /// The selector of the segment.
    pub selector: Selector,

    /// The access rights of the segment.
    pub access: SegmentAccess,
}
