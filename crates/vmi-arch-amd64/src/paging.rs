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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Page Table (PT) - the lowest level, pointing directly to 4KB pages.
    Pt,

    /// Page Directory (PD) - can point to PTs or 2MB large pages.
    Pd,

    /// Page Directory Pointer Table (PDPT) - can point to PDs or 1GB large.
    /// pages
    Pdpt,

    /// Page Map Level 4 (PML4) - the highest level in 4-level paging.
    Pml4,
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

    /// Checks if the page is accessible in user mode.
    /// Note: Returns true for user mode, false for supervisor mode.
    pub fn supervisor(self) -> bool {
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
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("present", &self.present())
            .field("write", &self.write())
            .field("supervisor", &self.supervisor())
            .field("page_level_write_through", &self.page_level_write_through())
            .field("page_level_cache_disable", &self.page_level_cache_disable())
            .field("accessed", &self.accessed())
            .field("dirty", &self.dirty())
            .field("large", &self.large())
            .field("global", &self.global())
            .field("pfn", &self.pfn())
            .finish()
    }
}
