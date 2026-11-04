use super::WindowsMmProtection;

/// A Windows PTE in one of its formats.
///
/// The format of an invalid PTE depends on its bits and on whether it is a
/// PTE of a page table or a prototype PTE. A PTE of a page table with the
/// prototype bit set points to a prototype PTE, and a prototype PTE with the
/// same bit set points to a subsection. [`WindowsOs::pte`] decodes a PTE of a
/// page table, and [`WindowsOs::prototype_pte`] decodes a prototype PTE.
///
/// # Implementation Details
///
/// Corresponds to `_MMPTE`.
///
/// [`WindowsOs::pte`]: crate::WindowsOs::pte
/// [`WindowsOs::prototype_pte`]: crate::WindowsOs::prototype_pte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsPte {
    /// A valid PTE.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPTE_HARDWARE`.
    Hardware,

    /// A PTE of a page in transition.
    ///
    /// The page is in memory, but the PTE is not valid.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPTE_TRANSITION`.
    Transition {
        /// The protection that the PTE's `Protection` bits hold.
        protection: WindowsMmProtection,
    },

    /// A PTE of a page table that points to a prototype PTE.
    ///
    /// The prototype PTE or the VAD holds the protection of the page.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPTE_PROTOTYPE`.
    Prototype,

    /// A prototype PTE of a file-backed page that is not in memory.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPTE_SUBSECTION`.
    Subsection {
        /// The protection that the PTE's `Protection` bits hold.
        protection: WindowsMmProtection,
    },

    /// A PTE of a demand-zero page or of a page in a paging file.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MMPTE_SOFTWARE`.
    Software {
        /// The protection that the PTE's `Protection` bits hold.
        protection: WindowsMmProtection,
    },
}

impl WindowsPte {
    /// Returns the protection of the page, or `None` when the PTE does not
    /// hold it.
    pub fn protection(&self) -> Option<WindowsMmProtection> {
        match self {
            Self::Transition { protection }
            | Self::Subsection { protection }
            | Self::Software { protection } => Some(*protection),
            Self::Hardware | Self::Prototype => None,
        }
    }
}
