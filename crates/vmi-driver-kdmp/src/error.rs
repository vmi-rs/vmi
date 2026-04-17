/// Error type for the KDMP driver.
#[derive(thiserror::Error, Debug)]
pub enum KdmpDriverError {
    /// An error occurred while parsing a kernel dump file.
    #[error(transparent)]
    Kdmp(#[from] kdmp_parser::error::Error),

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

impl From<KdmpDriverError> for vmi_core::VmiError {
    fn from(value: KdmpDriverError) -> Self {
        match value {
            KdmpDriverError::Kdmp(kdmp_parser::error::Error::PageRead(
                kdmp_parser::error::PageReadError::NotPresent { gva, .. },
            )) => Self::page_fault((vmi_core::Va(u64::from(gva)), vmi_core::Pa(0))),
            KdmpDriverError::Kdmp(kdmp_parser::error::Error::PageRead(
                kdmp_parser::error::PageReadError::NotInDump {
                    gva: Some((gva, _)),
                    ..
                },
            )) => Self::page_fault((vmi_core::Va(u64::from(gva)), vmi_core::Pa(0))),
            KdmpDriverError::Kdmp(value) => Self::Driver(Box::new(value)),
            KdmpDriverError::Io(value) => Self::Io(value),
            KdmpDriverError::NotSupported => Self::NotSupported,
            KdmpDriverError::OutOfBounds => Self::OutOfBounds,
        }
    }
}
