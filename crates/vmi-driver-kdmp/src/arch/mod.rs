mod amd64;
pub(crate) mod header64;

use vmi_core::{Architecture, VcpuId};

use crate::{Error, KdmpDriver};

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Header type for the dump.
    type Header;

    /// Exception record type for the dump.
    type ExceptionRecord;

    /// Returns the dump header.
    fn header(driver: &KdmpDriver<Self>) -> Self::Header;

    /// Returns the registers of the specified vCPU.
    fn registers(driver: &KdmpDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error>;
}
