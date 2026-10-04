use vmi_core::Pa;

/// Mask of `TTBRn_EL1.BADDR`, `bits[47:1]`.
pub(crate) const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFE;

/// Extracts the translation table base physical address from a raw
/// `TTBRn_EL1` value.
///
/// `TTBRn_EL1.BADDR` is `bits[47:1]`. Bit 0 is the CnP flag and `bits[63:48]`
/// hold the ASID. 52-bit physical addresses (FEAT_LPA) are not supported.
pub fn ttbr_base(ttbr: u64) -> Pa {
    Pa(ttbr & TTBR_BADDR_MASK)
}
