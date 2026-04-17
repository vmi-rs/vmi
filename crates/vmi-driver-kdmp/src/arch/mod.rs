mod amd64;
pub(crate) mod header64;

use vmi_core::{Architecture, VcpuId, VmiError};

use crate::VmiKdmpDriver;

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Header type for the dump.
    type Header;

    /// Exception record type for the dump.
    type ExceptionRecord;

    /// Returns the dump header.
    fn header(driver: &VmiKdmpDriver<Self>) -> Self::Header;

    /// Returns the registers of the specified vCPU.
    fn registers(driver: &VmiKdmpDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, VmiError>;
}
