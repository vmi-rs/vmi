use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::Gfn;

/// Translation granule selected by `TCR_EL1.TG0`/`TG1`.
///
/// The granule fixes the page size and therefore the per-level index width and
/// the starting walk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    /// 4KB granule: 9-bit indices, 4KB pages, 48-bit VA walked from L0.
    _4K,

    /// 16KB granule: 11-bit indices, 16KB pages.
    _16K,

    /// 64KB granule: 13-bit indices, 64KB pages.
    _64K,
}

impl Granule {
    /// Returns the page size in bytes for the granule.
    pub fn page_size(self) -> u64 {
        match self {
            Self::_4K => 0x1000,
            Self::_16K => 0x4000,
            Self::_64K => 0x1_0000,
        }
    }

    /// Returns the number of bits used to address a byte within a page.
    pub fn page_shift(self) -> u32 {
        match self {
            Self::_4K => 12,
            Self::_16K => 14,
            Self::_64K => 16,
        }
    }
}

/// Stage-1 translation control decoded from `TCR_EL1`.
///
/// Captures the per-region granule and the region size that together fix the
/// starting walk level and the per-level index width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationControl {
    /// Page size granule for the region.
    pub granule: Granule,

    /// Region size in bits, `64 - TxSZ`.
    pub va_size: u32,
}

impl TranslationControl {
    /// Decodes the control fields for the region selected by `high`.
    ///
    /// Field positions are verified against the generated sysreg defs:
    /// `TCR_EL1.T0SZ` = bits[5:0], `T1SZ` = bits[21:16], `TG0` = bits[15:14],
    /// `TG1` = bits[31:30]. The granule encodings differ between TG0 and TG1
    /// and are taken from `TCR_EL1_TG0_*` / `TCR_EL1_TG1_*`.
    pub fn from_tcr(tcr: u64, high: bool) -> Option<Self> {
        let granule = match high {
            // TG1: 0b01 = 16K, 0b10 = 4K, 0b11 = 64K (0b00 reserved).
            true => match (tcr >> 30) & 0b11 {
                0b10 => Granule::_4K,
                0b01 => Granule::_16K,
                0b11 => Granule::_64K,
                _ => return None,
            },
            // TG0: 0b00 = 4K, 0b01 = 64K, 0b10 = 16K (0b11 reserved).
            false => match (tcr >> 14) & 0b11 {
                0b00 => Granule::_4K,
                0b10 => Granule::_16K,
                0b01 => Granule::_64K,
                _ => return None,
            },
        };

        let txsz = match high {
            true => (tcr >> 16) & 0x3f,
            false => tcr & 0x3f,
        };

        Some(Self {
            granule,
            va_size: (64 - txsz) as u32,
        })
    }

    /// Returns the number of VA bits resolved by a single table level.
    ///
    /// Each level consumes `page_shift - 3` bits, since a descriptor is 8 bytes
    /// (`2^3`) wide and a table fills exactly one page.
    pub fn index_bits(self) -> u32 {
        self.granule.page_shift() - 3
    }

    /// Returns the starting (highest) walk level for this region.
    ///
    /// The walk resolves `va_size - page_shift` bits across `index_bits`-wide
    /// levels, and the bottom level is always L3, so the starting level is
    /// counted up from L3.
    pub fn start_level(self) -> PageTableLevel {
        let resolved = self.va_size - self.granule.page_shift();
        let levels = resolved.div_ceil(self.index_bits());
        // L3 is the bottom level; subtract the level count from it.
        match levels {
            1 => PageTableLevel::L3,
            2 => PageTableLevel::L2,
            3 => PageTableLevel::L1,
            _ => PageTableLevel::L0,
        }
    }
}

/// The levels in the AArch64 stage-1 page table hierarchy for a 48-bit VA on
/// the 4KB granule.
///
/// L0 is table-only, L1 and L2 may hold block descriptors (1GB and 2MB
/// respectively), and L3 always describes a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Level 0 table: the highest level, table descriptors only.
    L0,

    /// Level 1 table: table descriptors or 1GB block descriptors.
    L1,

    /// Level 2 table: table descriptors or 2MB block descriptors.
    L2,

    /// Level 3 table: page descriptors only.
    L3,
}

impl PageTableLevel {
    /// Returns the next lower level in the page table hierarchy.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::L0 => Some(Self::L1),
            Self::L1 => Some(Self::L2),
            Self::L2 => Some(Self::L3),
            Self::L3 => None,
        }
    }

    /// Returns the next higher level in the page table hierarchy.
    pub fn previous(self) -> Option<Self> {
        match self {
            Self::L1 => Some(Self::L0),
            Self::L2 => Some(Self::L1),
            Self::L3 => Some(Self::L2),
            Self::L0 => None,
        }
    }
}

/// A stage-1 translation table descriptor.
///
/// The bit layout follows the AArch64 VMSA descriptor format verified against
/// `arch/arm64/include/asm/pgtable-hwdef.h`: bit 0 is the valid bit
/// (`PTE_VALID`), bits[1:0] are the type field (`PTE_TYPE_MASK`), and the
/// output address occupies bits[47:granule_shift] (`PTE_ADDR_LOW`).
#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Checks if the descriptor is valid (`PTE_VALID`, bit 0).
    pub fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if bits[1:0] mark a table or page descriptor (`0b11`).
    ///
    /// At table levels L0-L2 this means a table descriptor pointing at the next
    /// level. At L3 the same encoding (`PTE_TYPE_PAGE`) means a page
    /// descriptor.
    pub fn table_or_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Checks if bits[1:0] mark a block descriptor (`0b01`, `PxD_TYPE_SECT`).
    ///
    /// Only meaningful at L1 (1GB block) and L2 (2MB block).
    pub fn block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Checks the access flag (`PTE_AF`, bit 10).
    pub fn access_flag(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Extracts the output-address frame number for the given granule.
    ///
    /// Per `PTE_ADDR_LOW` the output address occupies bits[47:page_shift] in
    /// the descriptor. FEAT_LPA / 52-bit physical addresses are out of scope,
    /// so the high address bits (`PTE_ADDR_HIGH`) are not consulted.
    pub fn output_frame(self, granule: Granule) -> Gfn {
        let shift = granule.page_shift();
        // Output address bits run from page_shift up to and including bit 47.
        let mask = ((1u64 << (48 - shift)) - 1) << shift;
        Gfn::new((self.0 & mask) >> shift)
    }
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("valid", &self.valid())
            .field("table_or_page", &self.table_or_page())
            .field("block", &self.block())
            .field("access_flag", &self.access_flag())
            .field("raw", &format_args!("{:#018x}", self.0))
            .finish()
    }
}
