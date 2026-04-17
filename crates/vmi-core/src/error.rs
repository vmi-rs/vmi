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
    #[error("translation error ({:?}, len: {})", .0[0], .0.len())]
    Translation(PageFaults),

    /// The given address has invalid width.
    #[error("invalid address width")]
    InvalidAddressWidth,

    /// Invalid timeout.
    #[error("invalid timeout")]
    InvalidTimeout,

    /// Operation not supported.
    #[error("operation not supported")]
    NotSupported,

    /// Out of bounds.
    #[error("out of bounds")]
    OutOfBounds,

    /// Translation root not present.
    #[error("translation root not present")]
    RootNotPresent,

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// The view was not found.
    #[error("view not found")]
    ViewNotFound,

    /// Other error.
    #[error("{0}")]
    Other(&'static str),
}

/// A collection of page faults.
pub type PageFaults = smallvec::SmallVec<[AddressContext; 1]>;

impl VmiError {
    /// Boxes a driver-specific error into [`VmiError::Driver`].
    pub fn driver<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Driver(Box::new(err))
    }

    /// Boxes an OS-specific error into [`VmiError::Os`].
    pub fn os<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Os(Box::new(err))
    }

    /// Creates a new page fault error.
    pub fn page_fault(pf: impl Into<AddressContext>) -> Self {
        Self::Translation(smallvec::smallvec![pf.into()])
    }

    /// Creates a new page fault error with multiple page faults.
    pub fn page_faults(pfs: impl IntoIterator<Item = AddressContext>) -> Self {
        Self::Translation(pfs.into_iter().collect())
    }
}
