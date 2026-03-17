use smallvec::SmallVec;

use super::{PageTableEntry, PageTableLevel};
use vmi_core::Pa;

/// A single entry in the page table hierarchy during virtual address
/// translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationEntry {
    /// The level of the page table hierarchy this entry belongs to.
    pub level: PageTableLevel,

    /// The actual page table entry.
    pub entry: PageTableEntry,

    /// The physical address where this entry is located in memory.
    pub entry_address: Pa,
}

impl TranslationEntry {
    /// Checks if the entry is a leaf node in the page table hierarchy.
    pub fn is_leaf(&self) -> bool {
        self.entry.valid()
            && match self.level {
                PageTableLevel::L3 => self.entry.is_page(),
                PageTableLevel::L2 => self.entry.is_block(),
                PageTableLevel::L1 => self.entry.is_block(),
                PageTableLevel::L0 => false, // L0 cannot be a block with 4KB granule
            }
    }
}

/// Collection of translation entries, typically used in page table walks.
pub type TranslationEntries = SmallVec<[TranslationEntry; 4]>;

/// The result of a virtual address translation process.
#[derive(Debug)]
pub struct VaTranslation {
    /// The page table entries traversed during the translation process.
    pub(super) entries: TranslationEntries,

    /// The physical address if translation was successful.
    pub(super) pa: Option<Pa>,
}

impl VaTranslation {
    /// Returns the page table entries traversed during the translation.
    pub fn entries(&self) -> &[TranslationEntry] {
        &self.entries
    }

    /// Consumes the `VaTranslation` and returns the `TranslationEntries`.
    pub fn into_entries(self) -> TranslationEntries {
        self.entries
    }

    /// Returns the physical address if translation was successful.
    pub fn pa(&self) -> Option<Pa> {
        self.pa
    }

    /// Checks if all page table entries in the translation path are valid.
    pub fn valid(&self) -> bool {
        self.entries.iter().all(|entry| entry.entry.valid())
    }
}

impl IntoIterator for VaTranslation {
    type Item = TranslationEntry;
    type IntoIter = <TranslationEntries as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
