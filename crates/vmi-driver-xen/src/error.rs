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
    fn from(error: xen::XenError) -> Self {
        Self::Xen(error)
    }
}

impl From<Error> for vmi_core::VmiError {
    fn from(error: Error) -> Self {
        match error {
            Error::Xen(error) => Self::Driver(Box::new(error)),
            Error::Io(error) => Self::Io(error),
            Error::InvalidTimeout => Self::InvalidTimeout,
            Error::NotSupported => Self::NotSupported,
            Error::OutOfBounds => Self::OutOfBounds,
            Error::Timeout => Self::Timeout,
            Error::ViewNotFound => Self::ViewNotFound,
        }
    }
}
