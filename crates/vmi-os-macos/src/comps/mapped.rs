use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::VmiOsMapped};

use super::MacOsVnode;
use crate::{ArchAdapter, MacOs};

/// A file mapped into a memory region of a macOS process.
///
/// # Implementation Details
///
/// Corresponds to the `struct vnode` that backs the memory object of the
/// region.
pub struct MacOsMapped<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct vnode`.
    va: Va,
}

impl<Driver> VmiVa for MacOsMapped<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsMapped<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new mapped file from the address of its vnode.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, vnode: Va) -> Self {
        Self { vmi, va: vnode }
    }

    /// Returns the vnode of the mapped file.
    pub fn vnode(&self) -> MacOsVnode<'a, Driver> {
        MacOsVnode::new(self.vmi, self.va)
    }
}

impl<'a, Driver> VmiOsMapped<'a, Driver> for MacOsMapped<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the path of the mapped file.
    ///
    /// See [`MacOsVnode::path`] for how the path is built.
    fn path(&self) -> Result<Option<String>, VmiError> {
        self.vnode().path()
    }
}
