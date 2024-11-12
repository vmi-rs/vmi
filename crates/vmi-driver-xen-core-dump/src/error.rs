/// Error type for the Xen driver.
pub enum Error {
    /// An error occurred while parsing an ELF file.
    Elf(elf::ParseError),

    /// An I/O error occurred.
    Io(std::io::Error),

    /// Operation not supported.
    NotSupported,

    /// Out of bounds.
    OutOfBounds,
}

impl From<elf::ParseError> for Error {
    fn from(value: elf::ParseError) -> Self {
        Self::Elf(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<Error> for vmi_core::VmiError {
    fn from(value: Error) -> Self {
        match value {
            Error::Elf(value) => Self::Driver(Box::new(value)),
            Error::Io(value) => Self::Io(value),
            Error::NotSupported => Self::NotSupported,
            Error::OutOfBounds => Self::OutOfBounds,
        }
    }
}
