#[cfg(target_arch = "x86_64")]
mod amd64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

use std::os::fd::RawFd;

use vmi_core::{Architecture, VcpuId, VmiEvent, VmiEventResponse};

use crate::{Error, KvmDriver};

/// Architecture-specific adapter for KVM.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Convert ring event registers to architecture-specific registers.
    fn registers_from_ring(regs: &kvm::sys::kvm_vmi_regs) -> Self::Registers;

    /// Convert architecture-specific registers to ring event registers.
    fn registers_to_ring(regs: &Self::Registers) -> kvm::sys::kvm_vmi_regs;

    /// Read registers from a vCPU fd using KVM_GET_REGS + KVM_GET_SREGS + KVM_GET_MSRS.
    fn registers_from_vcpu(vcpu_fd: RawFd) -> Result<Self::Registers, Error>;

    /// Enable monitoring for a specific event type.
    fn monitor_enable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error>;

    /// Disable monitoring for a specific event type.
    fn monitor_disable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error>;

    /// Inject an interrupt into a vCPU.
    fn inject_interrupt(
        driver: &KvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), Error>;

    /// Process a raw ring event, convert it, call the handler, and write the response.
    fn process_event(
        driver: &KvmDriver<Self>,
        raw_event: &mut kvm::sys::kvm_vmi_ring_event,
        handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error>;

    /// Reset all VMI state (disable events, destroy views).
    fn reset_state(driver: &KvmDriver<Self>) -> Result<(), Error>;
}
