//! In-memory mock [`VmiDriver`](vmi_core::VmiDriver) for testing.
//!
//! Models guest physical pages, per-view GFN remappings, and memory-access
//! protection, records every operation for assertions, and can inject a fault
//! into any single driver call.

pub mod arch;
