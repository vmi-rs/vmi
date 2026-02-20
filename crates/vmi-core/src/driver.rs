//! VMI driver trait hierarchy.
//!
//! Defines the capabilities a VMI driver can provide. Each trait represents
//! an independent capability; drivers implement only the traits they support.
//!
//! # Trait hierarchy
//!
//! All sub-traits extend [`VmiDriver`], the base trait that carries the
//! [`Architecture`] associated type and VM metadata.
//!
//! ```text
//! VmiDriver (base: Architecture type + info)
//! ├── VmiRead                 read guest physical pages
//! ├── VmiWrite                write guest physical pages
//! ├── VmiQueryProtection      query EPT/NPT page permissions
//! ├── VmiSetProtection        modify EPT/NPT page permissions
//! ├── VmiQueryRegisters       get vCPU register state
//! ├── VmiSetRegisters         set vCPU register state
//! ├── VmiViewControl          manage EPT/NPT views
//! ├── VmiEventControl         monitor and intercept events
//! └── VmiVmControl            VM lifecycle, interrupt injection
//! ```
//!
//! # Convenience supertraits
//!
//! ```text
//! VmiMemory      = VmiRead + VmiWrite
//! VmiProtection  = VmiQueryProtection + VmiSetProtection
//! VmiRegisters   = VmiQueryRegisters + VmiSetRegisters
//! VmiFullDriver  = all of the above
//! ```
//!
//! # Examples
//!
//! A crash dump driver only needs read-only access:
//!
//! ```ignore
//! impl VmiDriver for MyDumpDriver { /* ... */ }
//! impl VmiRead for MyDumpDriver { /* ... */ }
//! impl VmiQueryRegisters for MyDumpDriver { /* ... */ }
//! ```
//!
//! A hypervisor-backed driver that implements everything automatically
//! satisfies [`VmiFullDriver`].

use std::time::Duration;

use crate::{
    Architecture, Gfn, MemoryAccess, MemoryAccessOptions, VcpuId, View, VmiError, VmiEvent,
    VmiEventResponse, VmiInfo, VmiMappedPage,
};

/// Base trait for all VMI driver sub-traits.
///
/// This trait provides the associated [`Architecture`] type and the
/// fundamental `info()` method for querying VM metadata.
///
/// The `'static` lifetime is required in order to use the driver with the
/// [`VmiOs`](crate::VmiOs) enumerators.
pub trait VmiDriver: 'static {
    /// The architecture supported by the driver.
    type Architecture: Architecture + ?Sized;

    /// Returns information about the virtual machine.
    fn info(&self) -> Result<VmiInfo, VmiError>;
}

/// Capability to read guest physical memory pages.
pub trait VmiRead: VmiDriver {
    /// Reads a page of memory from the virtual machine.
    fn read_page(&self, gfn: Gfn) -> Result<VmiMappedPage, VmiError>;
}

/// Capability to write guest physical memory pages.
pub trait VmiWrite: VmiDriver {
    /// Writes data to a page of memory in the virtual machine.
    fn write_page(&self, gfn: Gfn, offset: u64, content: &[u8]) -> Result<VmiMappedPage, VmiError>;
}

/// Capability to query memory access permissions.
pub trait VmiQueryProtection: VmiDriver {
    /// Returns the memory access permissions for a specific GFN.
    fn memory_access(&self, gfn: Gfn, view: View) -> Result<MemoryAccess, VmiError>;
}

/// Capability to modify memory access permissions.
pub trait VmiSetProtection: VmiDriver {
    /// Sets the memory access permissions for a specific GFN.
    fn set_memory_access(&self, gfn: Gfn, view: View, access: MemoryAccess)
    -> Result<(), VmiError>;

    /// Sets the memory access permissions for a specific GFN with additional
    /// options.
    fn set_memory_access_with_options(
        &self,
        gfn: Gfn,
        view: View,
        access: MemoryAccess,
        options: MemoryAccessOptions,
    ) -> Result<(), VmiError>;
}

/// Capability to read vCPU registers.
pub trait VmiQueryRegisters: VmiDriver {
    /// Returns the registers of a specific virtual CPU.
    fn registers(
        &self,
        vcpu: VcpuId,
    ) -> Result<<Self::Architecture as Architecture>::Registers, VmiError>;
}

/// Capability to write vCPU registers.
pub trait VmiSetRegisters: VmiDriver {
    /// Sets the registers of a specific virtual CPU.
    fn set_registers(
        &self,
        vcpu: VcpuId,
        registers: <Self::Architecture as Architecture>::Registers,
    ) -> Result<(), VmiError>;
}

/// Capability to control event monitoring and delivery.
pub trait VmiEventControl: VmiDriver {
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
}

/// Capability to manage EPT/NPT views.
pub trait VmiViewControl: VmiDriver {
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
}

/// Capability to control VM lifecycle and GFN allocation.
pub trait VmiVmControl: VmiDriver {
    /// Pauses the virtual machine.
    fn pause(&self) -> Result<(), VmiError>;

    /// Resumes the virtual machine.
    fn resume(&self) -> Result<(), VmiError>;

    /// Allocates a specific GFN.
    fn allocate_gfn(&self, gfn: Gfn) -> Result<(), VmiError>;

    /// Frees a previously allocated GFN.
    fn free_gfn(&self, gfn: Gfn) -> Result<(), VmiError>;

    /// Injects an interrupt into a specific virtual CPU.
    fn inject_interrupt(
        &self,
        vcpu: VcpuId,
        interrupt: <Self::Architecture as Architecture>::Interrupt,
    ) -> Result<(), VmiError>;

    /// Resets the state of the VMI system.
    fn reset_state(&self) -> Result<(), VmiError>;
}

///////////////////////////////////////////////////////////////////////////////
// Convenience Supertraits
///////////////////////////////////////////////////////////////////////////////

/// Combined page read and write access.
pub trait VmiMemory: VmiRead + VmiWrite {}
impl<T: VmiRead + VmiWrite> VmiMemory for T {}

/// Combined memory access read and write.
pub trait VmiProtection: VmiQueryProtection + VmiSetProtection {}
impl<T: VmiQueryProtection + VmiSetProtection> VmiProtection for T {}

/// Combined register read and write access.
pub trait VmiRegisters: VmiQueryRegisters + VmiSetRegisters {}
impl<T: VmiQueryRegisters + VmiSetRegisters> VmiRegisters for T {}

/// All read-only VMI capabilities.
pub trait VmiReadAccess: VmiRead + VmiQueryProtection + VmiQueryRegisters {}
impl<T: VmiRead + VmiQueryProtection + VmiQueryRegisters> VmiReadAccess for T {}

/// All write/control VMI capabilities.
pub trait VmiWriteAccess: VmiWrite + VmiSetProtection + VmiSetRegisters {}
impl<T> VmiWriteAccess for T where T: VmiWrite + VmiSetProtection + VmiSetRegisters {}

/// A trait for implementing a VMI driver.
///
/// This is a convenience supertrait that combines all sub-traits.
/// Types implementing all sub-traits automatically implement `VmiDriver`
/// via a blanket implementation.
pub trait VmiFullDriver:
    VmiReadAccess + VmiWriteAccess + VmiEventControl + VmiViewControl + VmiVmControl
{
}

impl<T> VmiFullDriver for T where
    T: VmiReadAccess + VmiWriteAccess + VmiEventControl + VmiViewControl + VmiVmControl
{
}
