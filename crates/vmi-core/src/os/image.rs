use super::{OsArchitecture, OsImageExportedSymbol};
use crate::VmiError;

/// Represents information about a process in the target system.
pub trait VmiOsImage {
    /// Retrieves the architecture of an image at a given base address.
    fn architecture(&self) -> Result<OsArchitecture, VmiError>;

    /// Retrieves a list of exported symbols from an image at a given base
    /// address.
    fn exports(&self) -> Result<Vec<OsImageExportedSymbol>, VmiError>;
}
