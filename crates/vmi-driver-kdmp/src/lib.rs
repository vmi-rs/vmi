//! VMI driver for kernel memory dump.

mod arch;
mod driver;
mod error;

use std::path::Path;

use vmi_core::{
    Gfn, VcpuId, VmiDriver, VmiError, VmiInfo, VmiMappedPage,
    driver::{VmiQueryRegisters, VmiRead},
};

use self::driver::KdmpDriver;
pub use self::{
    arch::{
        ArchAdapter,
        header64::{ExceptionRecord64, Header64},
    },
    error::KdmpDriverError,
};

/// VMI driver for kernel memory dump.
pub struct VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    inner: KdmpDriver<Arch>,
}

impl<Arch> VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a new VMI driver for kernel memory dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        Ok(Self {
            inner: KdmpDriver::new(path)?,
        })
    }

    /// Returns the dump header.
    pub fn header(&self) -> Arch::Header {
        self.inner.header()
    }
}

impl<Arch> VmiDriver for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.inner.info()?)
    }
}

impl<Arch> VmiRead for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.read_page(gfn)?)
    }
}

impl<Arch> VmiQueryRegisters for VmiKdmpDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Ok(self.inner.registers(vcpu)?)
    }
}
