mod amd64;

use vmi_core::{Architecture, VcpuId, VmiEvent, VmiEventResponse};
use xen::{ctrl::VmEvent, Architecture as XenArchitecture};

use crate::{Error, XenDriver};

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    type XenArch: XenArchitecture;

    fn registers(driver: &XenDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error>;

    fn set_registers(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), Error>;

    fn monitor_enable(driver: &XenDriver<Self>, option: Self::EventMonitor) -> Result<(), Error>;

    fn monitor_disable(driver: &XenDriver<Self>, option: Self::EventMonitor) -> Result<(), Error>;

    fn inject_interrupt(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), Error>;

    fn process_event(
        driver: &XenDriver<Self>,
        event: &mut VmEvent,
        handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error>;

    fn reset_state(driver: &XenDriver<Self>) -> Result<(), Error>;
}
