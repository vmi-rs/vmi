use super::{OsArchitecture, OsImageExportedSymbol};
use crate::{Va, VmiError};

/// Represents information about a process in the target system.
pub trait VmiOsImage {
    /// Returns the base address of the image.
    fn base_address(&self) -> Va;

    /// Retrieves the architecture of an image at a given base address.
    fn architecture(&self) -> Result<OsArchitecture, VmiError>;

    /// Retrieves a list of exported symbols from an image at a given base
    /// address.
    fn exports(&self) -> Result<Vec<OsImageExportedSymbol>, VmiError>;
}
