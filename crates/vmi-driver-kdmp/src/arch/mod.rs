mod amd64;

use vmi_core::{Architecture, VcpuId};

use crate::{Error, KdmpDriver};

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    fn registers(driver: &KdmpDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error>;
}
