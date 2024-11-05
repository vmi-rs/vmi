use crate::{FromExt, MemoryAccess, VcpuId};

impl FromExt<VcpuId> for xen::VcpuId {
    fn from_ext(value: VcpuId) -> Self {
        Self(value.into())
    }
}

impl FromExt<xen::VcpuId> for VcpuId {
    fn from_ext(value: xen::VcpuId) -> Self {
        Self(value.into())
    }
}

impl FromExt<MemoryAccess> for xen::MemoryAccess {
    fn from_ext(value: MemoryAccess) -> Self {
        Self::from_bits_truncate(value.bits())
    }
}

impl FromExt<xen::MemoryAccess> for MemoryAccess {
    fn from_ext(value: xen::MemoryAccess) -> Self {
        Self::from_bits_truncate(value.bits())
    }
}
