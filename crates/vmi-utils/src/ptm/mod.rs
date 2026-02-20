//! Page table monitoring.
//!
//! Page table monitoring system that tracks changes in page table hierarchies.
//! It provides architecture-independent monitoring of virtual address
//! translations and automatically detects when monitored addresses become
//! available or unavailable in physical memory.
//!
//! The monitor tracks page table entries across the entire hierarchy
//! (e.g., PML4 through PT on AMD64) and generates events when pages are mapped
//! (page-in) or unmapped (page-out). Each monitored address can be associated
//! with a custom tag, allowing users to easily track monitored addresses during
//! debugging.
//!
//! The system is architecture-aware through its `ArchAdapter` trait system,
//! which allows for architecture-specific implementations while maintaining
//! a common interface.
//!
//! The AMD64 implementation serves as a reference, supporting the complete
//! 4-level paging structure.
//!
//! # Events
//!
//! The monitor generates two types of events through [`PageTableMonitorEvent`]:
//! - [`PageTableMonitorEvent::PageIn`]: When a monitored virtual address
//!   becomes backed by physical memory.
//! - [`PageTableMonitorEvent::PageOut`]: When a monitored virtual address is
//!   no longer backed by physical memory.
//!
//! Each event includes the affected virtual address context, physical address,
//! and associated view.
//!
//! # Limitations
//!
//! The monitor currently does not support monitoring of large pages (e.g., 2MB
//! or 1GB pages on AMD64).

mod arch;

use std::{fmt::Debug, hash::Hash};

use vmi_core::{
    AddressContext, Pa, VcpuId, View, VmiCore, VmiError,
    driver::{VmiRead, VmiSetProtection},
};

use self::arch::{ArchAdapter, PageTableMonitorArchAdapter};

/// Tag Type.
pub trait TagType: Debug + Copy + Eq + Hash {}
impl<T> TagType for T where T: Debug + Copy + Eq + Hash {}

/// Page Entry Update.
///
/// Page entry update that represents a change in a page table entry.
#[derive(Debug, Clone, Copy)]
pub struct PageEntryUpdate {
    /// View in which the update occurred.
    pub view: View,

    /// Virtual address context.
    pub ctx: AddressContext,

    /// Physical address.
    pub pa: Pa,
}

/// Page Table Monitor Event.
///
/// Page table monitor event that represents a change in the page table
/// hierarchy.
#[derive(Debug)]
pub enum PageTableMonitorEvent {
    /// Page In.
    ///
    /// This event is generated when a monitored virtual address becomes backed
    /// by physical memory.
    PageIn(PageEntryUpdate),

    /// Page Out.
    ///
    /// This event is generated when a monitored virtual address is no longer
    /// backed by physical memory.
    PageOut(PageEntryUpdate),
}

/// Page Table Monitor.
pub struct PageTableMonitor<Driver, Tag = &'static str>
where
    Driver: VmiRead + VmiSetProtection,
    Driver::Architecture: ArchAdapter<Driver, Tag>,
    Tag: TagType,
{
    inner: <Driver::Architecture as ArchAdapter<Driver, Tag>>::Impl,
}

impl<Driver, Tag> PageTableMonitor<Driver, Tag>
where
    Driver: VmiRead + VmiSetProtection,
    Driver::Architecture: ArchAdapter<Driver, Tag>,
    Tag: TagType,
{
    #[expect(clippy::new_without_default)]
    /// Creates a new page table monitor.
    pub fn new() -> Self {
        Self {
            inner: <Driver::Architecture as ArchAdapter<Driver, Tag>>::Impl::new(),
        }
    }

    /// Returns the number of monitored tables.
    pub fn monitored_tables(&self) -> usize {
        self.inner.monitored_tables()
    }

    /// Returns the number of monitored entries.
    pub fn monitored_entries(&self) -> usize {
        self.inner.monitored_entries()
    }

    /// Returns the number of paged-in entries.
    pub fn paged_in_entries(&self) -> usize {
        self.inner.paged_in_entries()
    }

    /// Dumps the monitor state.
    pub fn dump(&self) {
        self.inner.dump();
    }

    /// Monitors a virtual address.
    pub fn monitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
        tag: Tag,
    ) -> Result<(), VmiError> {
        self.inner.monitor(vmi, ctx, view, tag)
    }

    /// Unmonitors a virtual address.
    pub fn unmonitor(
        &mut self,
        vmi: &VmiCore<Driver>,
        ctx: impl Into<AddressContext>,
        view: View,
    ) -> Result<(), VmiError> {
        self.inner.unmonitor(vmi, ctx, view)
    }

    /// Unmonitors all virtual addresses.
    pub fn unmonitor_all(&mut self, vmi: &VmiCore<Driver>) {
        self.inner.unmonitor_all(vmi);
    }

    /// Unmonitors all virtual addresses associated with a view.
    pub fn unmonitor_view(&mut self, vmi: &VmiCore<Driver>, view: View) {
        self.inner.unmonitor_view(vmi, view);
    }

    /// Marks a page table entry as dirty.
    pub fn mark_dirty_entry(&mut self, entry_pa: Pa, view: View, vcpu_id: VcpuId) -> bool {
        self.inner.mark_dirty_entry(entry_pa, view, vcpu_id)
    }

    /// Processes dirty entries.
    pub fn process_dirty_entries(
        &mut self,
        vmi: &VmiCore<Driver>,
        vcpu_id: VcpuId,
    ) -> Result<Vec<PageTableMonitorEvent>, VmiError> {
        self.inner.process_dirty_entries(vmi, vcpu_id)
    }
}
