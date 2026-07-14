use crate::{FromExt, MemoryAccess, MemoryAccessOptions, VcpuId};

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
        if value == xen::MemoryAccess::RX2RW {
            return Self::RX;
        }

        if value == xen::MemoryAccess::N2RWX {
            return Self::empty();
        }

        if value == xen::MemoryAccess::R_PW {
            return Self::R;
        }

        Self::from_bits_truncate(value.bits())
    }
}

impl FromExt<xen::MemoryAccess> for MemoryAccessOptions {
    fn from_ext(value: xen::MemoryAccess) -> Self {
        if value == xen::MemoryAccess::R_PW {
            return Self::IGNORE_PAGE_WALK_UPDATES;
        }

        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{FromExt, MemoryAccess, MemoryAccessOptions};

    #[test]
    fn converts_special_xen_memory_access() {
        assert_eq!(
            MemoryAccess::from_ext(xen::MemoryAccess::RX2RW),
            MemoryAccess::RX
        );
        assert_eq!(
            MemoryAccess::from_ext(xen::MemoryAccess::N2RWX),
            MemoryAccess::empty()
        );
        assert_eq!(
            MemoryAccess::from_ext(xen::MemoryAccess::R_PW),
            MemoryAccess::R
        );
    }

    #[test]
    fn converts_xen_memory_access_options() {
        assert_eq!(
            MemoryAccessOptions::from_ext(xen::MemoryAccess::R_PW),
            MemoryAccessOptions::IGNORE_PAGE_WALK_UPDATES
        );
        assert_eq!(
            MemoryAccessOptions::from_ext(xen::MemoryAccess::RX2RW),
            MemoryAccessOptions::empty()
        );
        assert_eq!(
            MemoryAccessOptions::from_ext(xen::MemoryAccess::N2RWX),
            MemoryAccessOptions::empty()
        );
        assert_eq!(
            MemoryAccessOptions::from_ext(xen::MemoryAccess::RWX),
            MemoryAccessOptions::empty()
        );
    }
}
