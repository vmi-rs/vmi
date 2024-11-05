use crate::{Pa, Va};

/// An error that can occur when working with the VMI.
#[derive(thiserror::Error, Debug)]
pub enum VmiError {
    /// An error occurred in the VMI driver.
    #[error(transparent)]
    Driver(Box<dyn std::error::Error>),

    /// An OS-specific error occurred.
    #[error(transparent)]
    Os(Box<dyn std::error::Error>),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error occurred while parsing symbols.
    #[error(transparent)]
    Isr(#[from] isr_macros::Error),

    /// A page fault occurred.
    #[error("Page not present ({:?}, len: {})", .0[0], .0.len())]
    PageFault(PageFaults),

    /// The given address has invalid width.
    #[error("Invalid address width")]
    InvalidAddressWidth,

    /// The given timeout is invalid.
    #[error("The given timeout is invalid.")]
    InvalidTimeout,

    /// Operation not supported.
    #[error("Operation not supported.")]
    NotSupported,

    /// Out of bounds.
    #[error("Out of bounds")]
    OutOfBounds,

    /// Root not present.
    #[error("Root not present")]
    RootNotPresent,

    /// Timeout.
    #[error("Operation timed out.")]
    Timeout,

    /// The view was not found.
    #[error("The view was not found.")]
    ViewNotFound,

    /// Other error.
    #[error("{0}")]
    Other(&'static str),
}

/// A page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageFault {
    /// The virtual address that caused the page fault.
    pub address: Va,

    /// The root of the page table hierarchy.
    pub root: Pa,
}

/// A collection of page faults.
pub type PageFaults = smallvec::SmallVec<[PageFault; 1]>;

impl From<(Va, Pa)> for PageFault {
    fn from((address, root): (Va, Pa)) -> Self {
        Self { address, root }
    }
}

impl VmiError {
    /// Creates a new page fault error.
    pub fn page_fault(pf: impl Into<PageFault>) -> Self {
        Self::PageFault(smallvec::smallvec![pf.into()])
    }

    /// Creates a new page fault error with multiple page faults.
    pub fn page_faults(pfs: impl IntoIterator<Item = PageFault>) -> Self {
        Self::PageFault(pfs.into_iter().collect())
    }
}
