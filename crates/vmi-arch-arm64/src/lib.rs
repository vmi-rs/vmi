//! ARM64 (AArch64) architecture definitions.

mod address;
mod event;
mod interrupt;
mod paging;
mod registers;
mod translation;

use vmi_core::{
    AccessContext, AddressContext, Architecture, Gfn, MemoryAccess, Pa, Va, VmiCore, VmiError,
    arch::GpRegisters as _, driver::VmiRead,
};

pub use self::{
    address::{ttbr_base, ttbr_base_frame},
    event::{EventInterrupt, EventMemoryAccess, EventMonitor, EventReason, EventSinglestep},
    interrupt::{Interrupt, InterruptType},
    paging::{Granule, PageTableEntry, PageTableLevel, TranslationControl},
    registers::{GpRegisters, Registers},
};

/// ARM64 architecture.
#[derive(Debug)]
pub struct Arm64;

impl Architecture for Arm64 {
    const PAGE_SIZE: u64 = 0x1000;
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xFFFFFFFFFFFFF000;

    // BRK #0, encoded little-endian.
    const BREAKPOINT: &'static [u8] = &[0x00, 0x00, 0x20, 0xD4];

    type Registers = Registers;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = SpecialRegister;

    type EventMonitor = EventMonitor;
    type EventReason = EventReason;

    fn gfn_from_pa(pa: Pa) -> Gfn {
        Gfn(pa.0 >> Self::PAGE_SHIFT)
    }

    fn pa_from_gfn(gfn: Gfn) -> Pa {
        Pa(gfn.0 << Self::PAGE_SHIFT)
    }

    fn pa_offset(pa: Pa) -> u64 {
        pa.0 & !Self::PAGE_MASK
    }

    fn va_align_down(va: Va) -> Va {
        Self::va_align_down_for(va, PageTableLevel::L3)
    }

    fn va_align_down_for(va: Va, level: Self::PageTableLevel) -> Va {
        va & !level_size_mask(level)
    }

    fn va_align_up(va: Va) -> Va {
        Self::va_align_up_for(va, PageTableLevel::L3)
    }

    fn va_align_up_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = level_size_mask(level);
        (va + mask) & !mask
    }

    fn va_offset(va: Va) -> u64 {
        Self::va_offset_for(va, PageTableLevel::L3)
    }

    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64 {
        va.0 & level_size_mask(level)
    }

    fn va_index(va: Va) -> u64 {
        Self::va_index_for(va, PageTableLevel::L3)
    }

    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64 {
        // The trait helpers describe the 4KB granule (9-bit indices), the
        // Windows-on-ARM default. The TCR-driven walk in `translate_address`
        // honors the live granule instead.
        let shift = match level {
            PageTableLevel::L0 => 39,
            PageTableLevel::L1 => 30,
            PageTableLevel::L2 => 21,
            PageTableLevel::L3 => 12,
        };

        (va.0 >> shift) & 0x1ff
    }

    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        // The page-table root carries no granule or region-size information, so
        // assume the 4KB granule with a 48-bit region. A driver that wants to
        // honor a non-default TCR can call `translate_address_with` directly.
        let control = TranslationControl::from_tcr(16, false)
            .expect("4K granule with T0SZ=16 is a valid TCR configuration");
        translation::translate(vmi, va, root, control)
    }
}

impl Arm64 {
    /// Translates `va` to a physical address under an explicit `TCR_EL1`
    /// configuration.
    ///
    /// Selects the region from bit 55 of `va` to read the matching granule and
    /// region size from `tcr`, then walks the stage-1 tables rooted at `root`.
    pub fn translate_address_with<Driver>(
        vmi: &VmiCore<Driver>,
        va: Va,
        root: Pa,
        tcr: u64,
    ) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        let high = (va.0 >> 55) & 1 != 0;
        let control = match TranslationControl::from_tcr(tcr, high) {
            Some(control) => control,
            None => return Err(VmiError::page_fault((va, root))),
        };

        translation::translate(vmi, va, root, control)
    }

    /// Walks the stage-1 tables for `va` and returns the raw 4KB (L3) leaf
    /// descriptor, even when it is not valid.
    ///
    /// Assumes the default 4KB granule with a 48-bit region, matching
    /// [`Architecture::translate_address`]. Returns `None` when no L3 leaf is
    /// reachable, that is, an intermediate descriptor is invalid or maps a
    /// block. The returned descriptor may be invalid: a paged-out or transition
    /// page leaves a Windows software PTE in the leaf slot, which a higher layer
    /// decodes.
    pub fn leaf_descriptor<Driver>(
        vmi: &VmiCore<Driver>,
        va: Va,
        root: Pa,
    ) -> Result<Option<PageTableEntry>, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        let control = TranslationControl::from_tcr(16, false)
            .expect("4K granule with T0SZ=16 is a valid TCR configuration");
        translation::leaf_descriptor(vmi, va, root, control)
    }
}

/// Uninhabited placeholder for AArch64 special-register monitoring.
#[derive(Debug, Clone, Copy)]
pub enum SpecialRegister {}

/// Returns the byte-size mask covered by a leaf at `level` on the 4KB granule.
///
/// L3 covers a 4KB page, L2 a 2MB block, L1 a 1GB block, and L0 a 512GB span.
fn level_size_mask(level: PageTableLevel) -> u64 {
    match level {
        PageTableLevel::L3 => 0xfff,
        PageTableLevel::L2 => 0x1fffff,
        PageTableLevel::L1 => 0x3fffffff,
        PageTableLevel::L0 => 0x7fffffffff,
    }
}

impl vmi_core::arch::GpRegisters for GpRegisters {
    type Architecture = Arm64;

    fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.pc = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.sp_el0
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.sp_el0 = sp;
    }

    fn result(&self) -> u64 {
        self.regs[0]
    }

    fn set_result(&mut self, result: u64) {
        self.regs[0] = result;
    }
}

impl vmi_core::arch::Registers for Registers {
    type Architecture = Arm64;

    type GpRegisters = GpRegisters;

    fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.pc = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.sp_el0
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.sp_el0 = sp;
    }

    fn result(&self) -> u64 {
        self.regs[0]
    }

    fn set_result(&mut self, result: u64) {
        self.regs[0] = result;
    }

    fn gp_registers(&self) -> GpRegisters {
        GpRegisters {
            regs: self.regs,
            sp_el0: self.sp_el0,
            pc: self.pc,
        }
    }

    fn set_gp_registers(&mut self, gp: &GpRegisters) {
        self.regs = gp.regs;
        self.sp_el0 = gp.sp_el0;
        self.pc = gp.pc;
    }

    fn address_width(&self) -> usize {
        // AArch64 is a 64-bit architecture.
        8
    }

    fn effective_address_width(&self) -> usize {
        // AArch32 execution states are out of scope.
        8
    }

    fn access_context(&self, va: Va) -> AccessContext {
        self.address_context(va).into()
    }

    fn address_context(&self, va: Va) -> AddressContext {
        (va, self.translation_root(va)).into()
    }

    fn translation_root(&self, va: Va) -> Pa {
        // Bit 55 of the VA selects the translation regime: set picks the high
        // half (TTBR1_EL1), clear picks the low half (TTBR0_EL1).
        let ttbr = match (va.0 >> 55) & 1 {
            0 => self.ttbr0_el1,
            _ => self.ttbr1_el1,
        };

        // TTBRn_EL1.BADDR is bits[47:1] (GENMASK(47, 1)); bit 0 is CnP. The
        // 52-bit PA path (FEAT_LPA) is out of scope.
        ttbr_base(ttbr)
    }

    fn return_address<Driver>(&self, _vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
    {
        // On AArch64 the return address lives in the link register (x30 / LR),
        // not on the stack, so no memory read is required.
        Ok(Va(self.regs[30]))
    }

    fn return_from_function<Driver>(
        &self,
        _vmi: &VmiCore<Driver>,
        value: u64,
    ) -> Result<Self::GpRegisters, VmiError>
    where
        Driver: VmiRead<Architecture = Arm64>,
    {
        // AAPCS64: the return address is in x30 (LR), not on the stack, so only
        // x0 and PC change. No stack-pointer adjustment.
        let mut gp = self.gp_registers();
        gp.set_result(value);
        gp.set_instruction_pointer(self.regs[30]);
        Ok(gp)
    }
}

impl vmi_core::arch::EventMemoryAccess for EventMemoryAccess {
    type Architecture = Arm64;

    fn pa(&self) -> Pa {
        self.pa
    }

    fn va(&self) -> Va {
        self.va
    }

    fn access(&self) -> MemoryAccess {
        self.access
    }
}

impl vmi_core::arch::EventInterrupt for EventInterrupt {
    type Architecture = Arm64;

    fn gfn(&self) -> Gfn {
        self.gfn
    }
}

impl vmi_core::arch::EventReason for EventReason {
    type Architecture = Arm64;

    fn as_memory_access(
        &self,
    ) -> Option<&impl vmi_core::arch::EventMemoryAccess<Architecture = Arm64>> {
        match self {
            EventReason::MemoryAccess(memory_access) => Some(memory_access),
            _ => None,
        }
    }

    fn as_interrupt(&self) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Arm64>> {
        match self {
            EventReason::Interrupt(interrupt) => Some(interrupt),
            _ => None,
        }
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Arm64>> {
        match self {
            EventReason::Interrupt(interrupt)
                if interrupt.interrupt.typ == InterruptType::Synchronous =>
            {
                Some(interrupt)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod hfn_tests {
    use vmi_core::{Architecture as _, Gfn, Hfn};

    use crate::Arm64;

    #[test]
    fn hfn_identity_when_host_equals_guest() {
        assert_eq!(
            Arm64::hfn_from_gfn(Gfn::new(0x102a60), 12),
            Hfn::new(0x102a60)
        );
    }

    #[test]
    fn hfn_collapses_4k_guest_into_16k_host() {
        // 0x102a60 and 0x102a61 share host frame 0x40a98 on a 16K host.
        assert_eq!(
            Arm64::hfn_from_gfn(Gfn::new(0x102a60), 14),
            Hfn::new(0x40a98)
        );
        assert_eq!(
            Arm64::hfn_from_gfn(Gfn::new(0x102a61), 14),
            Hfn::new(0x40a98)
        );
    }
}
