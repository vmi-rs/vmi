//! Architecture-specific page table monitor implementations.

#[cfg(feature = "arch-amd64")]
pub mod amd64;

#[cfg(all(test, feature = "arch-amd64"))]
mod amd64_tests;

use vmi_core::{Architecture, VmiDriver};

use super::{PageTableMonitorAdapter, TagType};

/// Adapter type trait for architecture-specific page table monitor implementations.
pub trait ArchAdapter<Driver, Tag>: Architecture
where
    Driver: VmiDriver,
    Tag: TagType,
{
    /// Architecture-specific page table monitor implementation.
    type Monitor: PageTableMonitorAdapter<Driver, Tag>;
}
