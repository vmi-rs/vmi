use std::fmt::Debug;

use vmi_core::{Gfn, Va};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Mask of the descriptor output address `bits[47:0]`.
///
/// FEAT_LPA and FEAT_LPA2 52-bit output addresses are not supported, so the
/// high address bits are never consulted.
const OUTPUT_ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Translation granule selected by `TCR_EL1.TG0` or `TCR_EL1.TG1`.
///
/// The granule fixes the page size and therefore the per-level index width
/// and the starting walk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    /// 4KB granule with 9-bit table indices.
    _4K,

    /// 16KB granule with 11-bit table indices.
    _16K,

    /// 64KB granule with 13-bit table indices.
    _64K,
}

impl Granule {
    /// Returns the page size in bytes.
    pub const fn page_size(self) -> u64 {
        1 << self.page_shift()
    }

    /// Returns the number of bits used to address a byte within a page.
    pub const fn page_shift(self) -> u32 {
        match self {
            Self::_4K => 12,
            Self::_16K => 14,
            Self::_64K => 16,
        }
    }

    /// Returns the number of VA bits resolved by a single table level.
    ///
    /// A descriptor is 8 bytes wide and a table fills exactly one page, so
    /// each level consumes `page_shift - 3` bits.
    pub const fn index_bits(self) -> u32 {
        self.page_shift() - 3
    }

    /// Checks if a block descriptor is permitted at `level`.
    ///
    /// Without FEAT_LPA and FEAT_LPA2, the 4KB granule permits 1GB blocks at
    /// L1 and 2MB blocks at L2. The 16KB and 64KB granules permit blocks only
    /// at L2, which map 32MB and 512MB respectively.
    pub const fn allows_block(self, level: PageTableLevel) -> bool {
        match self {
            Self::_4K => matches!(level, PageTableLevel::L1 | PageTableLevel::L2),
            Self::_16K | Self::_64K => matches!(level, PageTableLevel::L2),
        }
    }
}

/// Stage-1 translation control for one half of the address space, decoded
/// from `TCR_EL1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationControl {
    /// Page size granule for the region.
    pub granule: Granule,

    /// Region size in bits, equal to `64 - TxSZ`.
    pub va_size: u32,
}

impl TranslationControl {
    /// Decodes the control fields for the region selected by `high`.
    ///
    /// `T0SZ` is `bits[5:0]`, `TG0` `bits[15:14]`, `T1SZ` `bits[21:16]` and `TG1`
    /// `bits[31:30]`. The granule encodings differ between `TG0` and `TG1`.
    /// Returns `None` for a reserved granule encoding.
    pub fn from_tcr(tcr: u64, high: bool) -> Option<Self> {
        let (granule, txsz) = if high {
            // TG1: 0b01 = 16K, 0b10 = 4K, 0b11 = 64K, 0b00 is reserved.
            let granule = match (tcr >> 30) & 0b11 {
                0b10 => Granule::_4K,
                0b01 => Granule::_16K,
                0b11 => Granule::_64K,
                _ => return None,
            };

            (granule, (tcr >> 16) & 0x3f)
        }
        else {
            // TG0: 0b00 = 4K, 0b01 = 64K, 0b10 = 16K, 0b11 is reserved.
            let granule = match (tcr >> 14) & 0b11 {
                0b00 => Granule::_4K,
                0b10 => Granule::_16K,
                0b01 => Granule::_64K,
                _ => return None,
            };

            (granule, tcr & 0x3f)
        };

        Some(Self {
            granule,
            va_size: 64 - txsz as u32,
        })
    }

    /// Returns the starting (highest) walk level for this region.
    ///
    /// The walk resolves `va_size - page_shift` bits across levels of
    /// `index_bits` each, and the bottom level is always L3.
    pub const fn start_level(self) -> PageTableLevel {
        let resolved = self.va_size.saturating_sub(self.granule.page_shift());
        match resolved.div_ceil(self.granule.index_bits()) {
            0 | 1 => PageTableLevel::L3,
            2 => PageTableLevel::L2,
            3 => PageTableLevel::L1,
            _ => PageTableLevel::L0,
        }
    }

    /// Returns the lowest VA bit translated by a table at `level`.
    ///
    /// This is also the size, as a power of two, of the region mapped by a
    /// single descriptor at `level`.
    pub const fn level_shift(self, level: PageTableLevel) -> u32 {
        let levels_below = match level {
            PageTableLevel::L0 => 3,
            PageTableLevel::L1 => 2,
            PageTableLevel::L2 => 1,
            PageTableLevel::L3 => 0,
        };

        self.granule.page_shift() + levels_below * self.granule.index_bits()
    }

    /// Returns the table index for `va` at `level`.
    ///
    /// The index at the starting level is narrowed to the bits below
    /// `va_size`. Levels above the starting level always yield index zero.
    pub const fn index(self, va: Va, level: PageTableLevel) -> u64 {
        let shift = self.level_shift(level);
        if shift >= self.va_size {
            return 0;
        }

        let bits = self.va_size - shift;
        let bits = if bits < self.granule.index_bits() {
            bits
        }
        else {
            self.granule.index_bits()
        };

        (va.0 >> shift) & ((1 << bits) - 1)
    }

    /// Returns the offset of `va` within the region mapped by a descriptor at
    /// `level`.
    pub const fn offset(self, va: Va, level: PageTableLevel) -> u64 {
        va.0 & self.offset_mask(level)
    }

    /// Returns the mask of the bits covered by a descriptor at `level`.
    pub const fn offset_mask(self, level: PageTableLevel) -> u64 {
        (1 << self.level_shift(level)) - 1
    }
}

/// Fixed stage-1 paging configuration of a guest.
///
/// A geometry pins the translation granule and the VA size of both halves of
/// the address space at compile time, which lets [`Arm64`] implement the
/// constant page size required by [`vmi_core::Architecture`].
///
/// The supertraits allow derives on types that are generic over the geometry.
///
/// [`Arm64`]: crate::Arm64
pub trait PagingGeometry:
    Debug + Clone + Copy + Default + PartialEq + Eq + Send + Sync + 'static
{
    /// Translation granule of both halves of the address space.
    const GRANULE: Granule;

    /// Number of translated VA bits of both halves, equal to `64 - TxSZ`.
    const VA_BITS: u32;

    /// Returns the translation control described by the geometry.
    fn control() -> TranslationControl {
        TranslationControl {
            granule: Self::GRANULE,
            va_size: Self::VA_BITS,
        }
    }

    /// Checks if both halves of `tcr` (`TG0`/`T0SZ` and `TG1`/`T1SZ`) match
    /// the geometry.
    fn matches_tcr(tcr: u64) -> bool {
        let control = Some(Self::control());
        TranslationControl::from_tcr(tcr, false) == control
            && TranslationControl::from_tcr(tcr, true) == control
    }
}

/// 4KB granule with a 48-bit VA.
///
/// The walk starts at L0. L1 descriptors may map 1GB blocks and L2
/// descriptors may map 2MB blocks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Granule4KVa48;

impl PagingGeometry for Granule4KVa48 {
    const GRANULE: Granule = Granule::_4K;
    const VA_BITS: u32 = 48;
}

/// 16KB granule with a 47-bit VA.
///
/// The walk starts at L1 with 11-bit indices. Only L2 descriptors may map
/// 32MB blocks, and an L1 block descriptor faults.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Granule16KVa47;

impl PagingGeometry for Granule16KVa47 {
    const GRANULE: Granule = Granule::_16K;
    const VA_BITS: u32 = 47;
}

/// The levels of the AArch64 stage-1 page table hierarchy.
///
/// L3 always describes a page. Which of the higher levels exist and which of
/// them may hold block descriptors depends on the granule and the VA size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Level 0 table.
    L0,

    /// Level 1 table.
    L1,

    /// Level 2 table.
    L2,

    /// Level 3 table, holding page descriptors only.
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
/// Bit 0 is the valid bit, `bits[1:0]` are the type field and the output
/// address occupies `bits[47:page_shift]`.
#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Checks if the descriptor is valid (bit 0).
    pub fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if `bits[1:0]` mark a table or page descriptor (`0b11`).
    ///
    /// Above L3 this encoding is a table descriptor pointing at the next
    /// level. At L3 the same encoding is a page descriptor.
    pub fn table_or_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Checks if `bits[1:0]` mark a block descriptor (`0b01`).
    pub fn block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Checks the access flag (bit 10).
    pub fn access_flag(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Returns the output address with the bits below `shift` cleared.
    ///
    /// Pass the page shift for table and page descriptors, and the level
    /// shift for block descriptors.
    pub fn output_address(self, shift: u32) -> u64 {
        self.0 & OUTPUT_ADDRESS_MASK & !((1 << shift) - 1)
    }

    /// Returns the output frame number for the given granule.
    pub fn output_frame(self, granule: Granule) -> Gfn {
        Gfn::new(self.output_address(granule.page_shift()) >> granule.page_shift())
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
