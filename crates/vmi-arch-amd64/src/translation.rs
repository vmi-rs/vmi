use smallvec::SmallVec;

use super::{PageTableEntry, PageTableLevel};
use crate::Pa;

/// A single entry in the page table hierarchy during virtual address
/// translation.
///
/// This struct encapsulates information about a specific page table entry,
/// including its level in the paging hierarchy, the entry itself, and its
/// physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationEntry {
    /// The level of the page table hierarchy this entry belongs to (e.g., PML4,
    /// PDPT, PD, PT).
    pub level: PageTableLevel,

    /// The actual page table entry, containing flags and the physical address
    /// of the next level.
    pub entry: PageTableEntry,

    /// The physical address where this entry is located in memory.
    pub entry_address: Pa,
}

impl TranslationEntry {
    /// Checks if the entry is a leaf node in the page table hierarchy.
    pub fn is_leaf(&self) -> bool {
        self.entry.present()
            && match self.level {
                PageTableLevel::Pt => true,
                PageTableLevel::Pd => self.entry.large(),
                PageTableLevel::Pdpt => self.entry.large(),
                PageTableLevel::Pml4 => self.entry.large(),
            }
    }
}

/// Collection of translation entries, typically used in page table walks.
pub type TranslationEntries = SmallVec<[TranslationEntry; 4]>;

/// The result of a virtual address translation process.
///
/// This struct encapsulates the information gathered during a page table walk,
/// including all the page table entries traversed and the final physical
/// address (if successful).
#[derive(Debug)]
pub struct VaTranslation {
    /// The page table entries traversed during the translation process.
    pub(super) entries: TranslationEntries,

    /// The physical address corresponding to the virtual address, if the
    /// translation was successful.
    pub(super) pa: Option<Pa>,
}

impl VaTranslation {
    /// Returns the page table entries traversed during the translation process.
    pub fn entries(&self) -> &[TranslationEntry] {
        &self.entries
    }

    /// Consumes the `VaTranslation` and returns the `TranslationEntries`.
    ///
    /// This method is useful when you need to take ownership of the entries
    /// collection.
    pub fn into_entries(self) -> TranslationEntries {
        self.entries
    }

    /// Returns the physical address resulting from the translation, if
    /// successful.
    pub fn pa(&self) -> Option<Pa> {
        self.pa
    }

    /// Checks if all page table entries in the translation path are present (P
    /// flag set).
    pub fn present(&self) -> bool {
        self.entries.iter().all(|entry| entry.entry.present())
    }

    /// Checks if all page table entries in the translation path are writable
    /// (R/W flag set).
    pub fn write(&self) -> bool {
        self.entries.iter().all(|entry| entry.entry.write())
    }

    /// Checks if all page table entries in the translation path are accessible
    /// in supervisor mode (U/S flag clear).
    pub fn supervisor(&self) -> bool {
        self.entries.iter().all(|entry| entry.entry.supervisor())
    }
}

impl IntoIterator for VaTranslation {
    type Item = TranslationEntry;
    type IntoIter = <TranslationEntries as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
