use vmi_core::{Architecture as _, Gfn, Pa};

use crate::Aarch64;

/// Extract the base address from a TTBR value.
///
/// Masks out ASID bits [63:48] and CnP bit [0].
pub fn ttbr_to_pa(ttbr: u64) -> Pa {
    Pa(ttbr & 0x0000_FFFF_FFFF_F000)
}

/// Extract the guest frame number from a TTBR value.
pub fn ttbr_to_gfn(ttbr: u64) -> Gfn {
    Aarch64::gfn_from_pa(ttbr_to_pa(ttbr))
}
