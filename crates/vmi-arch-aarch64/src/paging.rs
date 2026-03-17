use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use vmi_core::{Gfn, Pa};

/// The levels in the AArch64 page table hierarchy (4KB granule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Page Table (L3) — 4KB pages.
    L3,
    /// Page Middle Directory (L2) — 2MB blocks possible.
    L2,
    /// Page Upper Directory (L1) — 1GB blocks possible.
    L1,
    /// Page Global Directory (L0) — 512GB region.
    L0,
}

impl PageTableLevel {
    /// Returns the next lower level in the page table hierarchy.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::L3 => None,
            Self::L2 => Some(Self::L3),
            Self::L1 => Some(Self::L2),
            Self::L0 => Some(Self::L1),
        }
    }

    /// Returns the next higher level in the page table hierarchy.
    pub fn previous(self) -> Option<Self> {
        match self {
            Self::L3 => Some(Self::L2),
            Self::L2 => Some(Self::L1),
            Self::L1 => Some(Self::L0),
            Self::L0 => None,
        }
    }
}

/// A page table entry (descriptor) in the AArch64 paging structures.
#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Checks if the descriptor is valid (bit 0).
    pub fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if this is a table descriptor (bits [1:0] == 0b11).
    /// Only meaningful at L0-L2.
    pub fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Checks if this is a block descriptor (bits [1:0] == 0b01).
    /// Only meaningful at L1/L2.
    pub fn is_block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Checks if this is a page descriptor (bits [1:0] == 0b11 at L3).
    /// Same encoding as table but at leaf level.
    pub fn is_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Extracts the output address (bits [47:12]) as a physical address.
    pub fn output_address(self) -> Pa {
        Pa(self.0 & 0x0000_FFFF_FFFF_F000)
    }

    /// Extracts the page frame number from the output address.
    pub fn pfn(self) -> Gfn {
        Gfn::new(self.output_address().0 >> 12)
    }

    /// Access flag (bit 10).
    pub fn af(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Access permission bits [7:6].
    pub fn ap(self) -> u8 {
        ((self.0 >> 6) & 0x3) as u8
    }

    /// Execute-never for EL0 / UXN (bit 54).
    pub fn xn(self) -> bool {
        (self.0 >> 54) & 1 != 0
    }

    /// Privileged execute-never / PXN (bit 53).
    pub fn pxn(self) -> bool {
        (self.0 >> 53) & 1 != 0
    }
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("valid", &self.valid())
            .field("is_table", &self.is_table())
            .field("is_block", &self.is_block())
            .field("af", &self.af())
            .field("ap", &self.ap())
            .field("xn", &self.xn())
            .field("pxn", &self.pxn())
            .field("pfn", &self.pfn())
            .finish()
    }
}
