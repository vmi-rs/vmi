/// Error types for PE parsing.
#[derive(thiserror::Error, Debug)]
pub enum PeError {
    /// Invalid DOS magic.
    #[error("Invalid DOS magic")]
    InvalidDosMagic,

    /// Invalid DOS header size or alignment.
    #[error("Invalid DOS header size or alignment")]
    InvalidDosHeaderSizeOrAlignment,

    /// Invalid NT headers size or alignment.
    #[error("Invalid NT headers size or alignment")]
    InvalidNtHeadersSizeOrAlignment,

    /// Invalid PE magic.
    #[error("Invalid PE magic")]
    InvalidPeMagic,

    /// Invalid PE optional header magic.
    #[error("Invalid PE optional header magic")]
    InvalidPeOptionalHeaderMagic,

    /// PE optional header size is too small.
    #[error("PE optional header size is too small")]
    PeOptionalHeaderSizeTooSmall,

    /// Invalid PE optional header size.
    #[error("Invalid PE optional header size")]
    InvalidPeOptionalHeaderSize,

    /// Invalid PE number of RVA and sizes.
    #[error("Invalid PE number of RVA and sizes")]
    InvalidPeNumberOfRvaAndSizes,

    /// Invalid export table.
    #[error("Invalid export table")]
    InvalidExportTable,
}

impl From<PeError> for vmi_core::VmiError {
    fn from(err: PeError) -> Self {
        vmi_core::VmiError::Os(err.into())
    }
}
