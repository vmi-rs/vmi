//! VMI driver for Xen core dump.

mod arch;
mod driver;
mod dump;
mod error;

use std::path::Path;

use vmi_core::{
    Architecture, Gfn, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

pub use self::error::Error;
use self::{arch::ArchAdapter, driver::XenCoreDumpDriver};

/// VMI driver for Xen core dump.
pub struct VmiXenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    inner: XenCoreDumpDriver<Arch>,
}

impl<Arch> VmiXenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    /// Creates a new VMI driver for Xen core dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        Ok(Self {
            inner: XenCoreDumpDriver::new(path)?,
        })
    }
}

impl<Arch> VmiDriver for VmiXenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.inner.info()?)
    }
}

impl<Arch> VmiRead for VmiXenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.read_page(gfn)?)
    }
}

impl<Arch> VmiQueryRegisters for VmiXenCoreDumpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Ok(self.inner.registers(vcpu)?)
    }
}
