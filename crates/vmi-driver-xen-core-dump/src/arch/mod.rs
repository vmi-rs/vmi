mod amd64;

use vmi_core::{Architecture, VcpuId, VmiError};

use crate::VmiXenCoreDumpDriver;

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Returns the registers of the specified vCPU.
    fn registers(
        driver: &VmiXenCoreDumpDriver<Self>,
        vcpu: VcpuId,
    ) -> Result<Self::Registers, VmiError>;
}
