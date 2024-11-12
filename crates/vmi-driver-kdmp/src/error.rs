/// Error type for the Xen driver.
pub enum Error {
    /// An error occurred while parsing a kernel dump file.
    Kdmp(kdmp_parser::KdmpParserError),

    /// An I/O error occurred.
    Io(std::io::Error),

    /// Operation not supported.
    NotSupported,

    /// Out of bounds.
    OutOfBounds,
}

impl From<kdmp_parser::KdmpParserError> for Error {
    fn from(value: kdmp_parser::KdmpParserError) -> Self {
        Self::Kdmp(value)
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
            Error::Kdmp(kdmp_parser::KdmpParserError::AddrTranslation(
                kdmp_parser::AddrTranslationError::Virt(gva, _),
            )) => Self::page_fault((vmi_core::Va(u64::from(gva)), vmi_core::Pa(0))),
            Error::Kdmp(value) => Self::Driver(Box::new(value)),
            Error::Io(value) => Self::Io(value),
            Error::NotSupported => Self::NotSupported,
            Error::OutOfBounds => Self::OutOfBounds,
        }
    }
}
