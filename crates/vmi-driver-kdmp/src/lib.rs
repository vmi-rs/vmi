//! VMI driver for Xen core dump.

mod arch;
mod driver;
mod error;

use std::{path::Path, time::Duration};

use vmi_core::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiDriver, VmiError,
    VmiEvent, VmiEventResponse, VmiInfo, VmiMappedPage,
};

pub use self::error::Error;
use self::{arch::ArchAdapter, driver::KdmpDriver};

/// VMI driver for Xen core dump.
pub struct VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    inner: KdmpDriver<Arch>,
}

impl<Arch> VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    /// Creates a new VMI driver for Xen core dump.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, VmiError> {
        Ok(Self {
            inner: KdmpDriver::new(path)?,
        })
    }
}

impl<Arch> VmiDriver for VmiKdmpDriver<Arch>
where
    Arch: Architecture + ArchAdapter,
{
    type Architecture = Arch;

    fn info(&self) -> Result<VmiInfo, VmiError> {
        Ok(self.inner.info()?)
    }

    fn pause(&self) -> Result<(), VmiError> {
        Ok(self.inner.pause()?)
    }

    fn resume(&self) -> Result<(), VmiError> {
        Ok(self.inner.resume()?)
    }

    fn registers(&self, vcpu: VcpuId) -> Result<Arch::Registers, VmiError> {
        Ok(self.inner.registers(vcpu)?)
    }

    fn set_registers(&self, vcpu: VcpuId, registers: Arch::Registers) -> Result<(), VmiError> {
        Ok(self.inner.set_registers(vcpu, registers)?)
    }

    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError> {
        Ok(self.inner.memory_access(gfn, view)?)
    }

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

    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.read_page(gfn)?)
    }

    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError> {
        Ok(self.inner.write_page(gfn, offset, content)?)
    }

    fn allocate_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        Ok(self.inner.allocate_gfn(gfn)?)
    }

    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError> {
        Ok(self.inner.free_gfn(gfn)?)
    }

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

    fn monitor_enable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Ok(self.inner.monitor_enable(option)?)
    }

    fn monitor_disable(&self, option: Arch::EventMonitor) -> Result<(), VmiError> {
        Ok(self.inner.monitor_disable(option)?)
    }

    fn inject_interrupt(&self, vcpu: VcpuId, interrupt: Arch::Interrupt) -> Result<(), VmiError> {
        Ok(self.inner.inject_interrupt(vcpu, interrupt)?)
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

    fn reset_state(&self) -> Result<(), VmiError> {
        Ok(self.inner.reset_state()?)
    }
}
