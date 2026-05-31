//! Conversions between vmi-core and KVM types that are not arch-specific.

use vmi_core::MemoryAccess;

use crate::convert::FromExt;

impl FromExt<MemoryAccess> for u8 {
    fn from_ext(value: MemoryAccess) -> Self {
        let mut bits = 0u8;
        if value.contains(MemoryAccess::R) {
            bits |= kvm::sys::KVM_VMI_ACCESS_R as u8;
        }
        if value.contains(MemoryAccess::W) {
            bits |= kvm::sys::KVM_VMI_ACCESS_W as u8;
        }
        if value.contains(MemoryAccess::X) {
            bits |= kvm::sys::KVM_VMI_ACCESS_X as u8;
        }
        bits
    }
}

impl FromExt<u8> for MemoryAccess {
    fn from_ext(value: u8) -> Self {
        let mut access = MemoryAccess::empty();
        if value & kvm::sys::KVM_VMI_ACCESS_R as u8 != 0 {
            access |= MemoryAccess::R;
        }
        if value & kvm::sys::KVM_VMI_ACCESS_W as u8 != 0 {
            access |= MemoryAccess::W;
        }
        if value & kvm::sys::KVM_VMI_ACCESS_X as u8 != 0 {
            access |= MemoryAccess::X;
        }
        access
    }
}
