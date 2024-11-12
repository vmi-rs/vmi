/// Error types for Linux operations.
#[derive(thiserror::Error, Debug)]
pub enum LinuxError {
    /// Corrupted struct.
    #[error("Corrupted struct: {0}")]
    CorruptedStruct(&'static str),
}

impl From<LinuxError> for vmi_core::VmiError {
    fn from(value: LinuxError) -> Self {
        vmi_core::VmiError::Os(value.into())
    }
}
