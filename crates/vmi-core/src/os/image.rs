use serde::{Deserialize, Serialize};

use super::VmiOs;
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
    fn architecture(&self) -> Result<Option<VmiOsImageArchitecture>, VmiError>;

    /// Returns the exported symbols.
    fn exports(&self) -> Result<Vec<VmiOsImageSymbol>, VmiError>;
}

/// The architecture of the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmiOsImageArchitecture {
    /// The x86 architecture.
    X86,

    /// The x86-64 architecture.
    Amd64,
}

/// An exported symbol from an image (e.g., DLL or .so file).
#[derive(Debug, Serialize, Deserialize)]
pub struct VmiOsImageSymbol {
    /// The name of the symbol.
    pub name: String,

    /// The virtual address of the symbol.
    pub address: Va,
}
