use super::{VmiOs, VmiOsMapped as _, impl_predicate};
use crate::{MemoryAccess, Va, VmiDriver, VmiError, VmiVa};

impl_predicate! {
    /// Predicate used by [`VmiOsProcessExt::find_region`].
    ///
    /// [`VmiOsProcessExt::find_region`]: super::VmiOsProcessExt::find_region
    pub trait RegionPredicate & impl for &str {
        /// Matches a mapped region whose backing file path equals `self`
        /// case-insensitively.
        ///
        /// Private regions and mapped regions without a backing path
        /// always return `Ok(false)`. Regions do not carry a name of their
        /// own, so the backing-file path is the only string identifier a
        /// `&str` predicate can sensibly compare against.
        fn matches(&self, region: &Os::Region<'_>) -> Result<bool, VmiError> {
            match region.kind()?.into_mapped() {
                Some(mapped) if let Some(path) = mapped.path()?.as_deref() => {
                    let name = match path.rsplit_once(['\\', '/']) {
                        Some((_, name)) => name,
                        None => path,
                    };

                    Ok(name.eq_ignore_ascii_case(self))
                }
                _ => Ok(false),
            }
        }
    }

    #[any]
    pub struct AnyRegion;
}

/// A trait for memory regions.
///
/// This trait provides an abstraction over memory regions within a guest OS.
pub trait VmiOsRegion<'a, Driver>: VmiVa + 'a
where
    Driver: VmiDriver,
{
    /// The VMI OS type.
    type Os: VmiOs<Driver = Driver, Region<'a> = Self>;

    /// Returns the starting virtual address of the memory region.
    fn start(&self) -> Result<Va, VmiError>;

    /// Returns the ending virtual address of the memory region.
    fn end(&self) -> Result<Va, VmiError>;

    /// Returns the memory protection of the memory region.
    fn protection(&self) -> Result<MemoryAccess, VmiError>;

    /// Returns the memory region's kind.
    fn kind(&self) -> Result<VmiOsRegionKind<'a, Self::Os>, VmiError>;
}

/// Specifies the kind of memory region.
pub enum VmiOsRegionKind<'a, Os>
where
    Os: VmiOs + 'a,
{
    /// A private region of memory.
    ///
    /// Such regions are usually created by functions like `VirtualAlloc` on
    /// Windows.
    Private,

    /// A mapped region of memory. Might be backed by a file.
    ///
    /// Such regions are usually created by functions like `MapViewOfFile` on
    /// Windows.
    MappedData(Os::Mapped<'a>),

    /// A mapped image region of memory. Might be backed by a file.
    ///
    /// Such regions are usually created by functions like `MapViewOfFile` on
    /// Windows.
    MappedImage(Os::Mapped<'a>),
}

impl<'a, Os> VmiOsRegionKind<'a, Os>
where
    Os: VmiOs,
{
    /// Checks if the region is private.
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }

    /// Checks if the region is mapped.
    pub fn is_mapped(&self) -> bool {
        matches!(self, Self::MappedData(_) | Self::MappedImage(_))
    }

    /// Returns the mapped region.
    pub fn mapped(&self) -> Option<&Os::Mapped<'a>> {
        match self {
            Self::MappedData(mapped) | Self::MappedImage(mapped) => Some(mapped),
            _ => None,
        }
    }

    /// Returns the mapped region.
    pub fn into_mapped(self) -> Option<Os::Mapped<'a>> {
        match self {
            Self::MappedData(mapped) | Self::MappedImage(mapped) => Some(mapped),
            _ => None,
        }
    }
}
