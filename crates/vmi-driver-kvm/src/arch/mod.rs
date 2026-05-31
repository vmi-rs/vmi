//! Architecture adapter for the KVM driver.

mod amd64;

use std::time::Duration;

use vmi_core::{Architecture, VcpuId, VmiError, VmiEvent, VmiEventResponse};

use crate::VmiKvmDriver;

/// Architecture-specific behavior for the KVM driver.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Reads the registers of a vCPU via standard KVM ioctls.
    fn registers(driver: &VmiKvmDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, VmiError>;

    /// Writes the registers of a vCPU via standard KVM ioctls.
    fn set_registers(
        driver: &VmiKvmDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), VmiError>;

    /// Enables a monitor option via `KVM_VMI_CONTROL_EVENT`.
    fn monitor_enable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Disables a monitor option via `KVM_VMI_CONTROL_EVENT`.
    fn monitor_disable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Injects an interrupt via `KVM_VMI_INJECT_EVENT`.
    fn inject_interrupt(
        driver: &VmiKvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), VmiError>;

    /// Waits for and processes events on any ready ring, invoking the handler.
    fn process_event(
        driver: &VmiKvmDriver<Self>,
        timeout: Duration,
        handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), VmiError>;

    /// Disables all known monitors and resets view state.
    fn reset_state(driver: &VmiKvmDriver<Self>) -> Result<(), VmiError>;
}
