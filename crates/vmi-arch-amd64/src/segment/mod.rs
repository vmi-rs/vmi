mod descriptor;
pub use self::descriptor::SegmentDescriptor;

mod selector;
pub use self::selector::{DescriptorTable, Selector};

/// Determines the type of segment descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    /// The descriptor is for a system segment.
    System,

    /// The descriptor is for a code or data segment.
    CodeOrData,
}

/// Determines the default length for effective addresses and operands
/// referenced by instructions in the segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationSize {
    /// 16-bit addresses and 16-bit or 8-bit operands are assumed.
    Default,

    /// 32-bit addresses and 32-bit or 8-bit operands are assumed.
    Big,
}

/// Determines the scaling of the segment limit field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    /// The segment limit is interpreted in byte units.
    Byte,

    /// The segment limit is interpreted in 4-KByte units.
    Page4K,
}

/// The access rights of a segment descriptor.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct SegmentAccess(pub u32);

impl SegmentAccess {
    /// Indicates the segment or gate type and specifies the kinds of access
    /// that can be made to the segment and the direction of growth. The
    /// interpretation of this field depends on whether the descriptor type
    /// flag specifies an application (code or data) descriptor or a system
    /// descriptor. The encoding of the type field is different for code,
    /// data, and system descriptors.
    pub fn typ(self) -> u8 {
        (self.0 & 0b1111) as _
    }

    /// Specifies whether the segment descriptor is for a system segment (S flag
    /// is clear) or a code or data segment (S flag is set).
    pub fn descriptor_type(self) -> DescriptorType {
        if (self.0 >> 4) & 1 == 0 {
            DescriptorType::System
        }
        else {
            DescriptorType::CodeOrData
        }
    }

    /// Specifies the privilege level of the segment. The privilege level can
    /// range from 0 to 3, with 0 being the most privileged level. The DPL
    /// is used to control access to the segment. See Section 5.5, “Privilege
    /// Levels”, for a description of the relationship of the DPL to the CPL of
    /// the executing code segment and the RPL of a segment selector.
    pub fn descriptor_privilege_level(self) -> u8 {
        ((self.0 >> 5) & 0b11) as _
    }

    /// Indicates whether the segment is present in memory (set) or not present
    /// (clear). If this flag is clear, the processor generates a
    /// segment-not-present exception (#NP) when a segment selector that
    /// points to the segment descriptor is loaded into a segment register.
    /// Memory management software can use this flag to control which
    /// segments are actually loaded into physical memory at a given
    /// time. It offers a control in addition to paging for managing virtual
    /// memory.
    pub fn present(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// This bit is available for use by system software.
    pub fn available_bit(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// In IA-32e mode, bit 21 of the second doubleword of the segment
    /// descriptor indicates whether a code segment contains native 64-bit
    /// code. A value of 1 indicates instructions in this code segment
    /// are executed in 64-bit mode. A value of 0 indicates the instructions in
    /// this code segment are executed in compatibility mode. If L-bit is
    /// set, then D-bit must be cleared. When not in IA-32e mode
    /// or for non-code segments, bit 21 is reserved and should always be set to
    /// 0.
    pub fn long_mode(self) -> bool {
        (self.0 >> 9) & 1 != 0
    }

    /// Performs different functions depending on whether the segment descriptor
    /// is an executable code segment, an expand-down data segment, or a
    /// stack segment. (This flag should always be set to 1 for 32-bit code
    /// and data segments and to 0 for 16-bit code and data segments.)
    ///
    /// - Executable code segment. The flag is called the D flag and it
    ///   indicates the default length for effective addresses and operands
    ///   referenced by instructions in the segment. If the flag is set, 32-bit
    ///   addresses and 32-bit or 8-bit operands are assumed; if it is clear,
    ///   16-bit addresses and 16-bit or 8-bit operands are assumed. The
    ///   instruction prefix 66H can be used to select an operand size other
    ///   than the default, and the prefix 67H can be used select an address
    ///   size other than the default.
    ///
    /// - Stack segment (data segment pointed to by the SS register). The flag
    ///   is called the B (big) flag and it specifies the size of the stack
    ///   pointer used for implicit stack operations (such as pushes, pops, and
    ///   calls). If the flag is set, a 32-bit stack pointer is used, which is
    ///   stored in the 32-bit ESP register; if the flag is clear, a 16-bit
    ///   stack pointer is used, which is stored in the 16- bit SP register. If
    ///   the stack segment is set up to be an expand-down data segment
    ///   (described in the next paragraph), the B flag also specifies the upper
    ///   bound of the stack segment.
    ///
    /// - Expand-down data segment. The flag is called the B flag and it
    ///   specifies the upper bound of the segment. If the flag is set, the
    ///   upper bound is FFFFFFFFH (4 GBytes); if the flag is clear, the upper
    ///   bound is FFFFH (64 KBytes).
    pub fn operation_size(self) -> OperationSize {
        if (self.0 >> 10) & 1 == 0 {
            OperationSize::Default
        }
        else {
            OperationSize::Big
        }
    }

    /// Determines the scaling of the segment limit field. When the granularity
    /// flag is clear, the segment limit is interpreted in byte units; when
    /// flag is set, the segment limit is interpreted in 4-KByte units.
    /// (This flag does not affect the granularity of the base address; it is
    /// always byte granular.) When the granularity flag is set, the twelve
    /// least significant bits of an offset are not tested when checking the
    /// offset against the segment limit. For example, when the granularity flag
    /// is set, a limit of 0 results in valid offsets from 0 to 4095.
    pub fn granularity(self) -> Granularity {
        if (self.0 >> 11) & 1 == 0 {
            Granularity::Byte
        }
        else {
            Granularity::Page4K
        }
    }
}

impl From<u32> for SegmentAccess {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SegmentAccess> for u32 {
    fn from(value: SegmentAccess) -> Self {
        value.0
    }
}

impl std::fmt::Debug for SegmentAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("type", &self.typ())
            .field("descriptor_type", &self.descriptor_type())
            .field(
                "descriptor_privilege_level",
                &self.descriptor_privilege_level(),
            )
            .field("present", &self.present())
            .field("available_bit", &self.available_bit())
            .field("long_mode", &self.long_mode())
            .field("operation_size", &self.operation_size())
            .field("granularity", &self.granularity())
            .finish()
    }
}
