/// Error type for the KDMP driver.
pub enum Error {
    /// An error occurred while parsing a kernel dump file.
    Kdmp(kdmp_parser::error::Error),

    /// An I/O error occurred.
    Io(std::io::Error),

    /// Operation not supported.
    NotSupported,

    /// Out of bounds.
    OutOfBounds,
}

impl From<kdmp_parser::error::Error> for Error {
    fn from(value: kdmp_parser::error::Error) -> Self {
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
            Error::Kdmp(kdmp_parser::error::Error::PageRead(
                kdmp_parser::error::PageReadError::NotPresent { gva, .. },
            )) => Self::page_fault((vmi_core::Va(u64::from(gva)), vmi_core::Pa(0))),
            Error::Kdmp(kdmp_parser::error::Error::PageRead(
                kdmp_parser::error::PageReadError::NotInDump {
                    gva: Some((gva, _)),
                    ..
                },
            )) => Self::page_fault((vmi_core::Va(u64::from(gva)), vmi_core::Pa(0))),
            Error::Kdmp(value) => Self::Driver(Box::new(value)),
            Error::Io(value) => Self::Io(value),
            Error::NotSupported => Self::NotSupported,
            Error::OutOfBounds => Self::OutOfBounds,
        }
    }
}
