use vmi_core::VmiError;

/// Errors specific to the KVM VMI driver.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error from a KVM ioctl or system call.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The requested timeout is invalid.
    #[error("invalid timeout")]
    InvalidTimeout,

    /// The operation is not supported by this KVM version.
    #[error("not supported")]
    NotSupported,

    /// Access is out of bounds.
    #[error("out of bounds")]
    OutOfBounds,

    /// The operation timed out.
    #[error("timeout")]
    Timeout,

    /// The requested view was not found.
    #[error("view not found")]
    ViewNotFound,
}

impl From<kvm::KvmError> for Error {
    fn from(error: kvm::KvmError) -> Self {
        match error {
            kvm::KvmError::Io(err) => Error::Io(err),
            kvm::KvmError::Other(_) => Error::NotSupported,
        }
    }
}

impl From<Error> for VmiError {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(err) => VmiError::Io(err),
            Error::InvalidTimeout => VmiError::InvalidTimeout,
            Error::NotSupported => VmiError::NotSupported,
            Error::OutOfBounds => VmiError::OutOfBounds,
            Error::Timeout => VmiError::Timeout,
            Error::ViewNotFound => VmiError::ViewNotFound,
        }
    }
}
