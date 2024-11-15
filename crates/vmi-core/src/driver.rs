use std::time::Duration;

use crate::{
    Architecture, Gfn, MemoryAccess, VcpuId, View, VmiError, VmiEvent, VmiEventResponse, VmiInfo,
    VmiMappedPage,
};

/// A trait for implementing a VMI driver.
pub trait VmiDriver {
    /// The architecture supported by the driver.
    type Architecture: Architecture + ?Sized;

    /// Retrieves information about the virtual machine.
    fn info(&self) -> Result<VmiInfo, VmiError>;

    /// Pauses the virtual machine.
    fn pause(&self) -> Result<(), VmiError>;

    /// Resumes the virtual machine.
    fn resume(&self) -> Result<(), VmiError>;

    /// Retrieves the registers of a specific virtual CPU.
    fn registers(
        &self,
        vcpu: VcpuId,
    ) -> Result<<Self::Architecture as Architecture>::Registers, VmiError>;

    /// Sets the registers of a specific virtual CPU.
    fn set_registers(
        &self,
        vcpu: VcpuId,
        registers: <Self::Architecture as Architecture>::Registers,
    ) -> Result<(), VmiError>;

    /// Retrieves the memory access permissions for a specific GFN.
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError>;

    /// Sets the memory access permissions for a specific GFN.
    fn set_memory_access(&self, gfn: Gfn, view: View, access: MemoryAccess)
        -> Result<(), VmiError>;

    /// Reads a page of memory from the virtual machine.
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError>;

    /// Writes data to a page of memory in the virtual machine.
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError>;

    /// Allocates a specific GFN.
    fn allocate_gfn(&self, gfn: Gfn) -> Result<(), VmiError>;

    /// Frees a previously allocated GFN.
    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError>;

    /// Returns the default view for the virtual machine.
    fn default_view(&self) -> View;

    /// Creates a new view with the specified default access permissions.
    fn create_view(&self, default_access: MemoryAccess) -> Result<View, VmiError>;

    /// Destroys a previously created view.
    fn destroy_view(&self, view: View) -> Result<(), VmiError>;

    /// Switches to a different view.
    fn switch_to_view(&self, view: View) -> Result<(), VmiError>;

    /// Changes the mapping of a GFN in a specific view.
    fn change_view_gfn(&self, view: View, old_gfn: Gfn, new_gfn: Gfn) -> Result<(), VmiError>;

    /// Resets the mapping of a GFN in a specific view to its original state.
    fn reset_view_gfn(&self, view: View, gfn: Gfn) -> Result<(), VmiError>;

    /// Enables monitoring of specific events.
    fn monitor_enable(
        &self,
        option: <Self::Architecture as Architecture>::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Disables monitoring of specific events.
    fn monitor_disable(
        &self,
        option: <Self::Architecture as Architecture>::EventMonitor,
    ) -> Result<(), VmiError>;

    /// Injects an interrupt into a specific virtual CPU.
    fn inject_interrupt(
        &self,
        vcpu: VcpuId,
        interrupt: <Self::Architecture as Architecture>::Interrupt,
    ) -> Result<(), VmiError>;

    /// Returns the number of pending events.
    fn events_pending(&self) -> usize;

    /// Returns the time spent processing events.
    fn event_processing_overhead(&self) -> Duration;

    /// Waits for an event to occur and processes it with the provided handler.
    fn wait_for_event(
        &self,
        timeout: Duration,
        handler: impl FnMut(&VmiEvent<Self::Architecture>) -> VmiEventResponse<Self::Architecture>,
    ) -> Result<(), VmiError>;

    /// Resets the state of the VMI system.
    fn reset_state(&self) -> Result<(), VmiError>;
}
