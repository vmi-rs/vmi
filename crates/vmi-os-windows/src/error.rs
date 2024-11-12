/// Error types for Windows operations.
#[derive(thiserror::Error, Debug)]
pub enum WindowsError {
    /// Corrupted struct.
    #[error("Corrupted struct: {0}")]
    CorruptedStruct(&'static str),

    /// Corrupted struct.
    #[error(transparent)]
    Pe(#[from] crate::PeError),
}

impl From<WindowsError> for vmi_core::VmiError {
    fn from(value: WindowsError) -> Self {
        vmi_core::VmiError::Os(value.into())
    }
}
