use zerocopy::{FromBytes, IntoBytes};

/// A segment selector is a 16-bit identifier for a segment. It does not point
/// directly to the segment, but instead points to the segment descriptor that
/// defines the segment.
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes)]
pub struct Selector(pub u16);

/// A descriptor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorTable {
    /// The Global Descriptor Table.
    Gdt,

    /// The Local Descriptor Table.
    Ldt,
}

impl Selector {
    /// Specifies the privilege level of the selector. The privilege level can
    /// range from 0 to 3, with 0 being the most privileged level.
    pub fn request_privilege_level(self) -> u8 {
        (self.0 & 0b11) as _
    }

    /// Specifies the descriptor table to use: clearing this flag selects the
    /// GDT; setting this flag selects the current LDT.
    pub fn table(self) -> DescriptorTable {
        match self.0 >> 2 & 1 {
            0 => DescriptorTable::Gdt,
            1 => DescriptorTable::Ldt,
            _ => unreachable!(),
        }
    }

    /// Selects one of 8192 descriptors in the GDT or LDT. The processor
    /// multiplies the index value by 8 (the number of bytes in a segment
    /// descriptor) and adds the result to the base address of the GDT or
    /// LDT (from the GDTR or LDTR register, respectively).
    pub fn index(self) -> u16 {
        self.0 >> 3 & 0x1fff
    }
}

impl From<u16> for Selector {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Selector> for u16 {
    fn from(value: Selector) -> Self {
        value.0
    }
}

impl From<u32> for Selector {
    fn from(value: u32) -> Self {
        Self(value as u16)
    }
}

impl From<Selector> for u32 {
    fn from(value: Selector) -> Self {
        value.0 as u32
    }
}

impl std::fmt::Debug for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("request_privilege_level", &self.request_privilege_level())
            .field("table", &self.table())
            .field("index", &self.index())
            .finish()
    }
}
