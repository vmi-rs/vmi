//! Crate-local conversion trait and non-arch conversions.

use kvm::MemAccess;
use vmi_core::MemoryAccess;

/// Crate-local trait for conversion between types.
pub trait FromExt<T>: Sized {
    /// Converts a value from the source type.
    fn from_ext(value: T) -> Self;
}

impl FromExt<MemoryAccess> for MemAccess {
    fn from_ext(value: MemoryAccess) -> Self {
        let mut bits = MemAccess::empty();
        if value.contains(MemoryAccess::R) {
            bits |= MemAccess::R;
        }
        if value.contains(MemoryAccess::W) {
            bits |= MemAccess::W;
        }
        if value.contains(MemoryAccess::X) {
            bits |= MemAccess::X;
        }
        bits
    }
}

impl FromExt<MemAccess> for MemoryAccess {
    fn from_ext(value: MemAccess) -> Self {
        let mut access = MemoryAccess::empty();
        if value.contains(MemAccess::R) {
            access |= MemoryAccess::R;
        }
        if value.contains(MemAccess::W) {
            access |= MemoryAccess::W;
        }
        if value.contains(MemAccess::X) {
            access |= MemoryAccess::X;
        }
        access
    }
}
