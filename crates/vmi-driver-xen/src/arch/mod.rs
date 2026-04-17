mod amd64;

use vmi_core::{Architecture, VcpuId, VmiError, VmiEvent, VmiEventResponse};
use xen::{Architecture as XenArchitecture, ctrl::VmEvent};

use crate::VmiXenDriver;

/// Architecture-specific adapter for Xen.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Underlying Xen architecture type.
    type XenArch: XenArchitecture;

    /// Returns the registers of the specified vCPU.
    fn registers(driver: &VmiXenDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, VmiError>;

    /// Sets the registers of the specified vCPU.
    fn set_registers(
        driver: &VmiXenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), VmiError>;

    /// Enables the specified event monitor.
    fn monitor_enable(
        driver: &VmiXenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Disables the specified event monitor.
    fn monitor_disable(
        driver: &VmiXenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Injects an interrupt into the specified vCPU.
    fn inject_interrupt(
        driver: &VmiXenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), VmiError>;

    /// Processes a single VM event and invokes the handler.
    fn process_event(
        driver: &VmiXenDriver<Self>,
        event: &mut VmEvent,
        handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), VmiError>;

    /// Resets all driver-managed monitoring state.
    fn reset_state(driver: &VmiXenDriver<Self>) -> Result<(), VmiError>;
}
