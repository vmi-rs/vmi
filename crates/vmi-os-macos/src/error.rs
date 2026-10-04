use vmi_core::VmiError;

/// Error types for macOS operations.
#[derive(thiserror::Error, Debug)]
pub enum MacOsError {
    /// A kernel structure holds values that cannot be valid.
    #[error("corrupted struct: {0}")]
    CorruptedStruct(&'static str),

    /// A Mach-O header or load command is malformed.
    #[error("invalid Mach-O image: {0}")]
    InvalidMachO(&'static str),

    /// A segment of the profile has no counterpart in the kernel image in
    /// memory.
    #[error("kernel segment {0} not found in memory")]
    MissingSegment(String),

    /// A profile symbol lies outside every segment of the profile.
    #[error("symbol at {0:#x} is not inside any kernel segment")]
    SymbolOutsideSegment(u64),

    /// A thread ID does not fit into a [`ThreadId`].
    ///
    /// [`ThreadId`]: vmi_core::os::ThreadId
    #[error("thread ID {0} does not fit into 32 bits")]
    ThreadIdOutOfRange(u64),

    /// A Mach-O CPU type has no matching image architecture.
    #[error("unsupported CPU type {0:#x}")]
    UnsupportedCpuType(i32),
}

impl From<MacOsError> for VmiError {
    fn from(value: MacOsError) -> Self {
        VmiError::Os(value.into())
    }
}
