/// Error type for the Xen driver.
#[derive(thiserror::Error, Debug)]
pub enum XenDriverError {
    /// An error occurred in the Xen driver.
    #[error(transparent)]
    Xen(#[from] xen::XenError),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The given timeout is invalid.
    #[error("invalid timeout")]
    InvalidTimeout,

    /// Operation not supported.
    #[error("operation not supported")]
    NotSupported,

    /// Out of bounds.
    #[error("out of bounds")]
    OutOfBounds,

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// The view was not found.
    #[error("view not found")]
    ViewNotFound,
}

impl From<XenDriverError> for vmi_core::VmiError {
    fn from(value: XenDriverError) -> Self {
        match value {
            XenDriverError::Xen(value) => Self::Driver(Box::new(value)),
            XenDriverError::Io(value) => Self::Io(value),
            XenDriverError::InvalidTimeout => Self::InvalidTimeout,
            XenDriverError::NotSupported => Self::NotSupported,
            XenDriverError::OutOfBounds => Self::OutOfBounds,
            XenDriverError::Timeout => Self::Timeout,
            XenDriverError::ViewNotFound => Self::ViewNotFound,
        }
    }
}
