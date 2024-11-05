use serde::{Deserialize, Serialize};

use crate::Gfn;

/// Represents information about the VMI.
#[derive(Debug, Serialize, Deserialize)]
pub struct VmiInfo {
    /// The size of a page in bytes.
    pub page_size: u64,

    /// The shift value to convert a page number to a page address.
    pub page_shift: u64,

    /// The maximum guest frame number.
    pub max_gfn: Gfn,

    /// The number of virtual CPUs.
    pub vcpus: u16,
}
