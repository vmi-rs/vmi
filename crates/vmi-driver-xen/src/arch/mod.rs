mod amd64;

use vmi_core::{Architecture, VcpuId, VmiEvent, VmiEventResponse};
use xen::{Architecture as XenArchitecture, ctrl::VmEvent};

use crate::{XenDriver, XenDriverError};

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    type XenArch: XenArchitecture;

    fn registers(driver: &XenDriver<Self>, vcpu: VcpuId)
    -> Result<Self::Registers, XenDriverError>;

    fn set_registers(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), XenDriverError>;

    fn monitor_enable(
        driver: &XenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), XenDriverError>;

    fn monitor_disable(
        driver: &XenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), XenDriverError>;

    fn inject_interrupt(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), XenDriverError>;

    fn process_event(
        driver: &XenDriver<Self>,
        event: &mut VmEvent,
        handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), XenDriverError>;

    fn reset_state(driver: &XenDriver<Self>) -> Result<(), XenDriverError>;
}
