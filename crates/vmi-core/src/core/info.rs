use serde::{Deserialize, Serialize};

use crate::Gfn;

/// Represents information about the VMI.
#[derive(Debug, Serialize, Deserialize)]
pub struct VmiInfo {
    /// Guest-physical coordinate page size in bytes (the unit of `Gfn`).
    pub page_size: u64,

    /// log2(`page_size`): converts a `Gfn` to a guest physical address.
    pub page_shift: u64,

    /// Host page size in bytes (the unit of `Hfn`). Equals `page_size` unless
    /// the host pages are larger, as on a 16K arm64 host over a 4K guest.
    pub host_page_size: u64,

    /// log2(`host_page_size`): converts an `Hfn` to a host physical address.
    pub host_page_shift: u64,

    /// The maximum guest frame number.
    pub max_gfn: Gfn,

    /// The number of virtual CPUs.
    pub vcpus: u16,
}
