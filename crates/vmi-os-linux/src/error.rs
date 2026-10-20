use vmi_core::VmiError;

/// Error types for Linux operations.
#[derive(thiserror::Error, Debug)]
pub enum LinuxError {
    /// A kernel structure holds a value that cannot be right.
    #[error("corrupted struct: {0}")]
    CorruptedStruct(&'static str),

    /// The profile lacks a symbol or a structure that the crate needs.
    #[error("unsupported profile: {0}")]
    UnsupportedProfile(&'static str),

    /// The kernel works in a way that the crate does not support.
    #[error("unsupported kernel: {0}")]
    UnsupportedKernel(&'static str),
}

impl From<LinuxError> for VmiError {
    fn from(value: LinuxError) -> Self {
        VmiError::Os(value.into())
    }
}
