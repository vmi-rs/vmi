#[cfg(feature = "arch-amd64")]
pub mod amd64;

use vmi_core::{AddressContext, Architecture, Pa, VcpuId, View, VmiCore, VmiDriver, VmiError};

use super::{PageTableMonitorEvent, TagType};

/// Adapter type trait for architecture-specific page table monitor implementations.
pub trait ArchAdapter<Driver, Tag>: Architecture
where
    Driver: VmiDriver<Architecture = Self>,
    Tag: TagType,
{
    /// Architecture-specific page table monitor implementation.
    type Impl: PageTableMonitorArchAdapter<Driver, Tag>;
}

/// Adapter implementation trait for architecture-specific page table monitor implementations.
pub trait PageTableMonitorArchAdapter<Driver, Tag>
where
    Driver: VmiDriver,
{
    fn new() -> Self;

    fn monitored_tables(&self) -> usize;
    fn monitored_entries(&self) -> usize;
    fn paged_in_entries(&self) -> usize;
    fn dump(&self);

    fn monitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
        tag: Tag,
    ) -> Result<(), VmiError>;

    fn unmonitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError>;

    fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>);
    fn unmonitor_view(&mut self, vmi: &VmiCore<Driver>, view: View);

    fn mark_dirty_entry(&mut self, entry_pa: Pa, view: View, vcpu_id: VcpuId) -> bool;
    fn process_dirty_entries(
        &mut self,
        vmi: &VmiCore<Driver>,
        vcpu_id: VcpuId,
    ) -> Result<Vec<PageTableMonitorEvent>, VmiError>;
}
