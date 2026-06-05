use vmi_core::{Architecture as _, Gfn, Pa};

use crate::Arm64;

/// Extracts the translation-table base physical address from a raw `TTBRn_EL1`
/// value.
///
/// `TTBRn_EL1.BADDR` is bits[47:1] (`GENMASK(47, 1)`). Bit 0 is the CnP flag.
/// The 52-bit PA path (FEAT_LPA) is out of scope.
pub fn ttbr_base(ttbr: u64) -> Pa {
    Pa(ttbr & 0x0000_FFFF_FFFF_FFFE)
}

/// Returns the guest frame number of the translation-table base in `ttbr`.
pub fn ttbr_base_frame(ttbr: u64) -> Gfn {
    Arm64::gfn_from_pa(ttbr_base(ttbr))
}
