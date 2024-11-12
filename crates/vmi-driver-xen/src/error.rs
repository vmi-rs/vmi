/// Error type for the Xen driver.
pub enum Error {
    /// An error occurred in the Xen driver.
    Xen(xen::XenError),

    /// An I/O error occurred.
    Io(std::io::Error),

    /// The given timeout is invalid.
    InvalidTimeout,

    /// Operation not supported.
    NotSupported,

    /// Out of bounds.
    OutOfBounds,

    /// Timeout.
    Timeout,

    /// The view was not found.
    ViewNotFound,
}

impl From<xen::XenError> for Error {
    fn from(value: xen::XenError) -> Self {
        Self::Xen(value)
    }
}

impl From<Error> for vmi_core::VmiError {
    fn from(value: Error) -> Self {
        match value {
            Error::Xen(value) => Self::Driver(Box::new(value)),
            Error::Io(value) => Self::Io(value),
            Error::InvalidTimeout => Self::InvalidTimeout,
            Error::NotSupported => Self::NotSupported,
            Error::OutOfBounds => Self::OutOfBounds,
            Error::Timeout => Self::Timeout,
            Error::ViewNotFound => Self::ViewNotFound,
        }
    }
}
