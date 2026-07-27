//! Architecture-specific page table monitor implementations.

#[cfg(feature = "arch-amd64")]
pub mod amd64;

use vmi_core::{Architecture, VmiDriver};

use super::{PageTableMonitorAdapter, TagType};

/// Adapter type trait for architecture-specific page table monitor implementations.
pub trait ArchAdapter<Driver, Tag = &'static str>: Architecture
where
    Driver: VmiDriver,
    Tag: TagType,
{
    /// Architecture-specific page table monitor implementation.
    type Monitor: PageTableMonitorAdapter<Driver, Tag>;
}
