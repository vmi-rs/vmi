use serde::{Deserialize, Serialize};

/// A virtual CPU identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VcpuId(pub u16);

impl From<u16> for VcpuId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<VcpuId> for u16 {
    fn from(value: VcpuId) -> Self {
        value.0
    }
}

impl std::fmt::Display for VcpuId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
