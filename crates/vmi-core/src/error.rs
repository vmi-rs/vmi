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

    /// An error occurred while working with the ISR cache.
    #[error(transparent)]
    IsrCache(#[from] isr_cache::Error),

    /// A translation error occurred.
    #[error("translation error ({:?})", .0)]
    Translation(AddressContext),

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

    /// Creates a new translation error.
    pub fn translation(pf: impl Into<AddressContext>) -> Self {
        Self::Translation(pf.into())
    }
}
