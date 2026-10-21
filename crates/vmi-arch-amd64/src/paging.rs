use vmi_core::VmiError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::Gfn;

/// Supported paging modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingMode {
    /// 32-bit paging (4KB pages).
    Legacy,

    /// Physical Address Extension (allows 64GB of physical memory to be
    /// addressed by 32-bit systems).
    PAE,

    /// 64-bit paging (4-level paging).
    Ia32e,

    /// 64-bit paging with 5-level paging (allows for 57-bit linear addresses).
    Ia32eLA57,
}

impl PagingMode {
    /// Returns the address width (i.e. pointer size) of the paging mode in
    /// bytes.
    pub fn address_width(self) -> usize {
        match self {
            Self::Legacy => 4,
            Self::PAE => 4,
            Self::Ia32e => 8,
            Self::Ia32eLA57 => 8,
        }
    }
}

/// The levels in the page table hierarchy.
///
/// The levels count from the leaf, starting at 1, as the name of the PML4
/// (page map level 4) says. The PT is level 1. A level converts to its
/// number with `u8::from` and back with `PageTableLevel::try_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Page Table (PT) - the lowest level, pointing directly to 4KB pages.
    Pt = 1,

    /// Page Directory (PD) - can point to PTs or 2MB large pages.
    Pd = 2,

    /// Page Directory Pointer Table (PDPT) - can point to PDs or 1GB large.
    /// pages
    Pdpt = 3,

    /// Page Map Level 4 (PML4) - the highest level in 4-level paging.
    Pml4 = 4,
}

impl PageTableLevel {
    /// Returns the next lower level in the page table hierarchy.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Pt => None,
            Self::Pd => Some(Self::Pt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pml4 => Some(Self::Pdpt),
        }
    }

    /// Returns the next higher level in the page table hierarchy.
    pub fn previous(self) -> Option<Self> {
        match self {
            Self::Pt => Some(Self::Pd),
            Self::Pd => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pml4),
            Self::Pml4 => None,
        }
    }
}

impl From<PageTableLevel> for u8 {
    fn from(value: PageTableLevel) -> Self {
        value as Self
    }
}

impl TryFrom<u8> for PageTableLevel {
    type Error = VmiError;

    /// Returns the level with the given number.
    ///
    /// A number without a level fails with [`VmiError::OutOfBounds`].
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        [Self::Pt, Self::Pd, Self::Pdpt, Self::Pml4]
            .into_iter()
            .find(|level| u8::from(*level) == value)
            .ok_or(VmiError::OutOfBounds)
    }
}

/// A page table entry in the paging structures.
#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Checks if the page is present in physical memory.
    pub fn present(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if the page is writable.
    pub fn write(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// Checks if the page is accessible in user mode (U/S flag set).
    pub fn user(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// Checks if write-through caching is enabled for the page.
    pub fn page_level_write_through(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }

    /// Checks if caching is disabled for the page.
    pub fn page_level_cache_disable(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }

    /// Checks if the page has been accessed.
    pub fn accessed(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }

    /// Checks if the page has been written to.
    pub fn dirty(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }

    /// Checks if this entry refers to a large page.
    pub fn large(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// Checks if the page is global (shared between all processes).
    pub fn global(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// Extracts the page frame number from the entry.
    pub fn pfn(self) -> Gfn {
        const BITS: u64 = 40;
        const MASK: u64 = (1 << BITS) - 1;
        Gfn::new((self.0 >> 12) & MASK)
    }

    /// Checks if the XD (execute-disable) flag is set.
    ///
    /// With IA32_EFER.NXE set, instruction fetches from the region that the
    /// entry controls are not allowed. Without it, the bit is reserved.
    pub fn execute_disable(self) -> bool {
        (self.0 >> 63) & 1 != 0
    }
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("present", &self.present())
            .field("write", &self.write())
            .field("user", &self.user())
            .field("page_level_write_through", &self.page_level_write_through())
            .field("page_level_cache_disable", &self.page_level_cache_disable())
            .field("accessed", &self.accessed())
            .field("dirty", &self.dirty())
            .field("large", &self.large())
            .field("global", &self.global())
            .field("execute_disable", &self.execute_disable())
            .field("pfn", &self.pfn())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_converts_to_its_number_and_back() {
        let levels = [
            (PageTableLevel::Pt, 1),
            (PageTableLevel::Pd, 2),
            (PageTableLevel::Pdpt, 3),
            (PageTableLevel::Pml4, 4),
        ];

        for (level, number) in levels {
            assert_eq!(u8::from(level), number);
            assert_eq!(PageTableLevel::try_from(number).ok(), Some(level));
        }

        assert!(PageTableLevel::try_from(0).is_err());
        assert!(PageTableLevel::try_from(5).is_err());
    }
}
