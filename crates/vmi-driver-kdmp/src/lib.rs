//! VMI driver for kernel memory dump.

mod arch;
mod driver;
mod error;

use std::path::Path;

use vmi_core::{
    Architecture, Gfn, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

pub use self::error::Error;
use self::{arch::ArchAdapter, driver::KdmpDriver};

/// VMI driver for kernel memory dump.
pub struct VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    inner: KdmpDriver<Arch>,
}

impl<Arch> VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    /// Creates a new VMI driver for kernel memory dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        Ok(Self {
            inner: KdmpDriver::new(path)?,
        })
    }
}

impl<Arch> VmiDriver for VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.inner.info()?)
    }
}

impl<Arch> VmiRead for VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.read_page(gfn)?)
    }
}

impl<Arch> VmiQueryRegisters for VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Ok(self.inner.registers(vcpu)?)
    }
}
