/// Error type for the Xen core-dump driver.
#[derive(thiserror::Error, Debug)]
pub enum XenCoreDumpError {
    /// An error occurred while parsing an ELF file.
    #[error(transparent)]
    Elf(#[from] elf::ParseError),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Operation not supported.
    #[error("operation not supported")]
    NotSupported,

    /// Out of bounds.
    #[error("out of bounds")]
    OutOfBounds,
}

impl From<XenCoreDumpError> for vmi_core::VmiError {
    fn from(value: XenCoreDumpError) -> Self {
        match value {
            XenCoreDumpError::Elf(value) => Self::Driver(Box::new(value)),
            XenCoreDumpError::Io(value) => Self::Io(value),
            XenCoreDumpError::NotSupported => Self::NotSupported,
            XenCoreDumpError::OutOfBounds => Self::OutOfBounds,
        }
    }
}
