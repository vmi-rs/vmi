/// Error types for PE parsing.
#[derive(thiserror::Error, Debug)]
pub enum PeError {
    /// Invalid DOS magic.
    #[error("invalid DOS magic")]
    InvalidDosMagic,

    /// Invalid DOS header.
    #[error("invalid DOS header size or alignment")]
    InvalidDosHeader,

    /// Invalid NT headers.
    #[error("invalid NT headers size or alignment")]
    InvalidNtHeaders,

    /// Invalid PE magic.
    #[error("invalid PE magic")]
    InvalidPeMagic,

    /// Invalid optional header magic.
    #[error("invalid PE optional header magic")]
    InvalidOptionalHeaderMagic,

    /// PE optional header too small.
    #[error("PE optional header too small")]
    OptionalHeaderTooSmall,

    /// Invalid optional header size.
    #[error("invalid PE optional header size")]
    InvalidOptionalHeaderSize,

    /// Invalid data directory count.
    #[error("invalid data directory count")]
    InvalidDataDirectoryCount,

    /// Invalid export table.
    #[error("invalid export table")]
    InvalidExportTable,

    /// Invalid section table.
    #[error("invalid section table")]
    InvalidSectionTable,

    /// Invalid RVA.
    #[error("invalid RVA: {0}")]
    InvalidRva(u32),
}
