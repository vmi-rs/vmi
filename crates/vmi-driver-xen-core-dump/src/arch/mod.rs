mod amd64;

use vmi_core::{Architecture, VcpuId};

use crate::{Error, XenCoreDumpDriver};

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    fn registers(driver: &XenCoreDumpDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error>;
}
