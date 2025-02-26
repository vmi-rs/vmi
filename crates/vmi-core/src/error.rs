use crate::AddressContext;

/// An error that can occur when working with the VMI.
#[derive(thiserror::Error, Debug)]
pub enum VmiError {
    /// An error occurred in the VMI driver.
    #[error(transparent)]
    Driver(Box<dyn std::error::Error + Send + Sync>),

    /// An OS-specific error occurred.
    #[error(transparent)]
    Os(Box<dyn std::error::Error + Send + Sync>),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error occurred while parsing symbols.
    #[error(transparent)]
    Isr(#[from] isr_macros::Error),

    /// A translation error occurred.
    #[error("Translation error ({:?}, len: {})", .0[0], .0.len())]
    Translation(PageFaults),

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

/// A collection of page faults.
pub type PageFaults = smallvec::SmallVec<[AddressContext; 1]>;

impl VmiError {
    /// Creates a new page fault error.
    pub fn page_fault(pf: impl Into<AddressContext>) -> Self {
        Self::Translation(smallvec::smallvec![pf.into()])
    }

    /// Creates a new page fault error with multiple page faults.
    pub fn page_faults(pfs: impl IntoIterator<Item = AddressContext>) -> Self {
        Self::Translation(pfs.into_iter().collect())
    }
}
