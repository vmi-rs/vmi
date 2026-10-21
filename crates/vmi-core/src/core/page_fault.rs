use serde::{Deserialize, Serialize};

use super::{AddressContext, MemoryAccess, Pa, Va};

/// The reason for a page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PageFaultKind {
    /// An entry on the way to the page is not present.
    NotPresent,

    /// The page is mapped, but its access rights do not permit the access.
    Permission,
}

/// A guest access that the guest's page tables do not permit.
///
/// A translation fails with it inside [`VmiError::PageFault`] for an address
/// that is not mapped. [`Architecture::translate_access`] also fails with it
/// where the guest's own access would fault. [`Interrupt::page_fault`] turns
/// it into the exception that the guest's CPU would raise.
///
/// [`VmiError::PageFault`]: crate::VmiError::PageFault
/// [`Architecture::translate_access`]: crate::Architecture::translate_access
/// [`Interrupt::page_fault`]: crate::arch::Interrupt::page_fault
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PageFault {
    /// The virtual address of the access.
    pub va: Va,

    /// The translation root of the access.
    pub root: Pa,

    /// The access that faults.
    pub access: MemoryAccess,

    /// The reason for the fault.
    pub kind: PageFaultKind,

    /// The level of the entry that causes the fault.
    ///
    /// Levels count from the leaf, starting at 1. Level 1 is the last table,
    /// whose entries map pages. On AMD64 the PT is level 1 and the PML4 is
    /// level 4. A missing page reports the level of its missing entry, and a
    /// refused access the first entry from the root that refuses it.
    pub level: u8,
}

impl PageFault {
    /// Creates a page fault for an entry that is not present.
    pub fn not_present(ctx: impl Into<AddressContext>, access: MemoryAccess, level: u8) -> Self {
        Self::new(ctx.into(), access, PageFaultKind::NotPresent, level)
    }

    /// Creates a page fault for an access that the access rights do not
    /// permit.
    pub fn permission(ctx: impl Into<AddressContext>, access: MemoryAccess, level: u8) -> Self {
        Self::new(ctx.into(), access, PageFaultKind::Permission, level)
    }

    /// Creates a page fault.
    fn new(ctx: AddressContext, access: MemoryAccess, kind: PageFaultKind, level: u8) -> Self {
        Self {
            va: ctx.va,
            root: ctx.root,
            access,
            kind,
            level,
        }
    }
}

impl From<PageFault> for AddressContext {
    fn from(value: PageFault) -> Self {
        Self {
            va: value.va,
            root: value.root,
        }
    }
}
