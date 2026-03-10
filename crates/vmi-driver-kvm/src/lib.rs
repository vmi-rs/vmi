//! VMI driver for KVM hypervisor.

mod arch;
mod convert;
mod driver;
mod error;

use std::time::Duration;

use vmi_core::{
    Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiDriver, VmiError, VmiEvent,
    VmiEventResponse, VmiInfo, VmiMappedPage,
    driver::{
        VmiEventControl, VmiQueryProtection, VmiQueryRegisters, VmiRead, VmiSetProtection,
        VmiSetRegisters, VmiViewControl, VmiVmControl, VmiWrite,
    },
};

pub use self::error::Error;
use self::{
    arch::ArchAdapter,
    convert::{FromExt, IntoExt, TryFromExt},
    driver::KvmDriver,
};

/// VMI driver for KVM hypervisor.
pub struct VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    inner: KvmDriver<Arch>,
}

impl<Arch> VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    /// Creates a new VMI driver for KVM hypervisor.
    ///
    /// `vm_fd` is the raw file descriptor of the KVM VM.
    /// `num_vcpus` is the number of vCPUs.
    /// `vcpu_fds` are the raw file descriptors for each vCPU
    /// (for KVM_GET_REGS, KVM_GET_SREGS, KVM_GET_MSRS).
    pub fn new(
        vm_fd: std::os::fd::RawFd,
        num_vcpus: u32,
        vcpu_fds: Vec<std::os::fd::RawFd>,
    ) -> Result<Self, VmiError> {
        Ok(Self {
            inner: KvmDriver::new(vm_fd, num_vcpus, vcpu_fds)?,
        })
    }
}

impl<Arch> VmiDriver for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.inner.info()?)
    }
}

impl<Arch> VmiRead for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.read_page(gfn)?)
    }
}

impl<Arch> VmiWrite for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.write_page(gfn, offset, content)?)
    }
}

impl<Arch> VmiQueryProtection for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.inner.memory_access(gfn, view)?)
    }
}

impl<Arch> VmiSetProtection for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn set_memory_access(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
    ) -> Result<(), VmiError> {
        Ok(self.inner.set_memory_access(gfn, view, access)?)
    }

    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError> {
        Ok(self
            .inner
            .set_memory_access_with_options(gfn, view, access, options)?)
    }
}

impl<Arch> VmiQueryRegisters for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Ok(self.inner.registers(vcpu)?)
    }
}

impl<Arch> VmiSetRegisters for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn set_registers(&self, vcpu: VcpuId, registers: Arch::Registers) -> Result<(), VmiError> {
        Ok(self.inner.set_registers(vcpu, registers)?)
    }
}

impl<Arch> VmiViewControl for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn default_view(&self) -> View {
        self.inner.default_view()
    }

    fn create_view(&self, default_access: MemoryAccess) -> Result<View, VmiError> {
        Ok(self.inner.create_view(default_access)?)
    }

    fn destroy_view(&self, view: View) -> Result<(), VmiError> {
        Ok(self.inner.destroy_view(view)?)
    }

    fn switch_to_view(&self, view: View) -> Result<(), VmiError> {
        Ok(self.inner.switch_to_view(view)?)
    }

    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError> {
        Ok(self.inner.change_view_gfn(view, old_gfn, new_gfn)?)
    }

    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError> {
        Ok(self.inner.reset_view_gfn(view, gfn)?)
    }
}

impl<Arch> VmiEventControl for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn monitor_enable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Ok(self.inner.monitor_enable(option)?)
    }

    fn monitor_disable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Ok(self.inner.monitor_disable(option)?)
    }

    fn events_pending(&self) -> usize {
        self.inner.events_pending()
    }

    fn event_processing_overhead(&self) -> Duration {
        self.inner.event_processing_overhead()
    }

    fn wait_for_event(
        &self,
        timeout: Duration,
        handler: impl FnMut(&VmiEvent<Arch>) -> VmiEventResponse<Arch>,
    ) -> Result<(), VmiError> {
        Ok(self.inner.wait_for_event(timeout, handler)?)
    }
}

impl<Arch> VmiVmControl for VmiKvmDriver<Arch>
where
    Arch: ArchAdapter,
{
    fn pause(&self) -> Result<(), VmiError> {
        Ok(self.inner.pause()?)
    }

    fn resume(&self) -> Result<(), VmiError> {
        Ok(self.inner.resume()?)
    }

    fn allocate_gfn(&self) -> Result<Gfn, VmiError> {
        Ok(self.inner.allocate_gfn()?)
    }

    fn allocate_gfn_at(&self, _gfn: Gfn) -> Result<(), VmiError> {
        Err(VmiError::NotSupported)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        Ok(self.inner.free_gfn(gfn)?)
    }

    fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), VmiError> {
        Ok(self.inner.inject_interrupt(vcpu, interrupt)?)
    }

    fn reset_state(&self) -> Result<(), VmiError> {
        Ok(self.inner.reset_state()?)
    }
}
