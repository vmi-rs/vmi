use super::{OsArchitecture, OsImageExportedSymbol, VmiOs};
use crate::{Va, VmiDriver, VmiError, VmiVa};

/// A trait for executable images.
///
/// This trait provides an abstraction over executable images,
/// such as binaries and shared libraries, within a guest OS.
pub trait VmiOsImage<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver>;

    /// Returns the base address of the image.
    fn base_address(&self) -> Va;

    /// Returns the target architecture for which the image was compiled.
    fn architecture(&self) -> Result<OsArchitecture, VmiError>;

    /// Returns the exported symbols.
    fn exports(&self) -> Result<Vec<OsImageExportedSymbol>, VmiError>;
}
