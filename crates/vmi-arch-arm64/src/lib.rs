//! ARM64 (AArch64) architecture definitions.
//!
//! [`Arm64`] is generic over a [`PagingGeometry`] that fixes the translation
//! granule and the VA size of the guest at compile time:
//!
//! - [`Granule4KVa48`]: 4KB pages, 48-bit VA, walk from L0.
//! - [`Granule16KVa47`]: 16KB pages, 47-bit VA, walk from L1.
//!
//! The geometry must match the guest's `TCR_EL1`, which
//! [`PagingGeometry::matches_tcr`] verifies. Bit 55 of a virtual address
//! selects `TTBR1_EL1` (set) or `TTBR0_EL1` (clear) as the translation root.
//! Pointers read from guest memory may carry pointer authentication codes or
//! top-byte tags, which [`Arm64::canonical_address`] strips.

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

use self::address::TTBR_BADDR_MASK;
pub use self::{
    address::ttbr_base,
    event::{EventInterrupt, EventMemoryAccess, EventMonitor, EventReason, EventSinglestep},
    interrupt::{Interrupt, InterruptType},
    paging::{
        Granule, Granule4KVa48, Granule16KVa47, PageTableEntry, PageTableLevel, PagingGeometry,
        TranslationControl,
    },
    registers::{GpRegisters, Registers},
};

/// ARM64 architecture with a fixed paging geometry.
#[derive(Debug)]
pub struct Arm64<Geometry>(std::marker::PhantomData<Geometry>);

impl<Geometry> Architecture for Arm64<Geometry>
where
    Geometry: PagingGeometry,
{
    const PAGE_SIZE: u64 = Geometry::GRANULE.page_size();
    const PAGE_SHIFT: u64 = Geometry::GRANULE.page_shift() as u64;
    const PAGE_MASK: u64 = !(Self::PAGE_SIZE - 1);

    // BRK #0, encoded little-endian.
    const BREAKPOINT: &'static [u8] = &[0x00, 0x00, 0x20, 0xd4];

    type Registers = Registers<Geometry>;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = SpecialRegister;

    type EventMonitor = EventMonitor;
    type EventReason = EventReason<Geometry>;

    fn gfn_from_pa(pa: Pa) -> Gfn {
        Gfn(pa.0 >> Self::PAGE_SHIFT)
    }

    fn pa_from_gfn(gfn: Gfn) -> Pa {
        Pa(gfn.0 << Self::PAGE_SHIFT)
    }

    fn pa_in_gfn(gfn: Gfn, va: Va) -> Pa {
        Self::pa_in_gfn_for(gfn, va, PageTableLevel::L3)
    }

    fn pa_in_gfn_for(gfn: Gfn, va: Va, level: Self::PageTableLevel) -> Pa {
        Self::pa_from_gfn(gfn) + Self::va_offset_for(va, level)
    }

    fn pa_offset(pa: Pa) -> u64 {
        pa.0 & !Self::PAGE_MASK
    }

    fn va_align_down(va: Va) -> Va {
        Self::va_align_down_for(va, PageTableLevel::L3)
    }

    fn va_align_down_for(va: Va, level: Self::PageTableLevel) -> Va {
        va & !Geometry::control().offset_mask(level)
    }

    fn va_align_up(va: Va) -> Va {
        Self::va_align_up_for(va, PageTableLevel::L3)
    }

    fn va_align_up_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = Geometry::control().offset_mask(level);
        (va + mask) & !mask
    }

    fn va_offset(va: Va) -> u64 {
        Self::va_offset_for(va, PageTableLevel::L3)
    }

    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64 {
        Geometry::control().offset(va, level)
    }

    fn va_index(va: Va) -> u64 {
        Self::va_index_for(va, PageTableLevel::L3)
    }

    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64 {
        Geometry::control().index(va, level)
    }

    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        translation::translate(vmi, va, root)
    }
}

impl<Geometry> Arm64<Geometry>
where
    Geometry: PagingGeometry,
{
    /// Strips pointer authentication codes and top-byte tags from `raw`.
    ///
    /// Bit 55 selects the half of the address space and survives both PAC
    /// signing and tagging. When bit 55 is set, `bits[63:VA_BITS]` are set,
    /// otherwise they are cleared.
    pub fn canonical_address(raw: u64) -> Va {
        let mask = (1u64 << Geometry::VA_BITS) - 1;

        if (raw >> 55) & 1 != 0 {
            Va(raw | !mask)
        }
        else {
            Va(raw & mask)
        }
    }

    /// Walks the stage-1 tables for `va` and returns the raw L3 descriptor,
    /// even when it is not valid.
    ///
    /// Returns `None` when no L3 descriptor is reachable because an
    /// intermediate descriptor is invalid or maps a block. An invalid
    /// descriptor may still carry OS-specific software bits, which a higher
    /// layer can decode.
    pub fn leaf_descriptor<Driver>(
        vmi: &VmiCore<Driver>,
        va: Va,
        root: Pa,
    ) -> Result<Option<PageTableEntry>, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        translation::leaf_descriptor(vmi, va, root)
    }
}

/// Uninhabited placeholder for AArch64 special-register monitoring.
#[derive(Debug, Clone, Copy)]
pub enum SpecialRegister {}

/// Mask of the ASID `bits[63:48]` and the CnP bit 0 of `TTBRn_EL1`.
const TTBR_PRESERVED_MASK: u64 = !TTBR_BADDR_MASK;

impl<Geometry> vmi_core::arch::GpRegisters for GpRegisters<Geometry>
where
    Geometry: PagingGeometry,
{
    type Architecture = Arm64<Geometry>;

    fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.pc = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.sp
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.sp = sp;
    }

    fn result(&self) -> u64 {
        self.regs[0]
    }

    fn set_result(&mut self, result: u64) {
        self.regs[0] = result;
    }
}

impl<Geometry> vmi_core::arch::Registers for Registers<Geometry>
where
    Geometry: PagingGeometry,
{
    type Architecture = Arm64<Geometry>;

    type GpRegisters = GpRegisters<Geometry>;

    fn instruction_pointer(&self) -> u64 {
        self.pc
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.pc = ip;
    }

    fn stack_pointer(&self) -> u64 {
        if self.uses_sp_el1() {
            self.sp_el1
        }
        else {
            self.sp_el0
        }
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        if self.uses_sp_el1() {
            self.sp_el1 = sp;
        }
        else {
            self.sp_el0 = sp;
        }
    }

    fn result(&self) -> u64 {
        self.regs[0]
    }

    fn set_result(&mut self, result: u64) {
        self.regs[0] = result;
    }

    fn gp_registers(&self) -> GpRegisters<Geometry> {
        let mut gp = GpRegisters::default();
        gp.regs = self.regs;
        gp.sp = self.stack_pointer();
        gp.pc = self.pc;
        gp.pstate = self.pstate;
        gp
    }

    fn set_gp_registers(&mut self, gp: &GpRegisters<Geometry>) {
        self.regs = gp.regs;
        self.pc = gp.pc;
        self.pstate = gp.pstate;
        self.set_stack_pointer(gp.sp);
    }

    fn address_width(&self) -> usize {
        8
    }

    fn effective_address_width(&self) -> usize {
        // AArch32 execution states are not supported.
        8
    }

    fn access_context(&self, va: Va) -> AccessContext {
        self.address_context(va).into()
    }

    fn address_context(&self, va: Va) -> AddressContext {
        (va, self.translation_root(va)).into()
    }

    fn translation_root(&self, va: Va) -> Pa {
        if (va.0 >> 55) & 1 != 0 {
            ttbr_base(self.ttbr1_el1)
        }
        else {
            ttbr_base(self.ttbr0_el1)
        }
    }

    fn set_translation_root(&mut self, root: u64, va: Va) {
        let ttbr = if (va.0 >> 55) & 1 != 0 {
            &mut self.ttbr1_el1
        }
        else {
            &mut self.ttbr0_el1
        };

        *ttbr = (*ttbr & TTBR_PRESERVED_MASK) | (root & TTBR_BADDR_MASK);
    }

    fn return_address<Driver>(&self, _vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
    {
        // The return address lives in the link register (x30).
        Ok(Va(self.regs[30]))
    }

    fn return_from_function<Driver>(
        &self,
        _vmi: &VmiCore<Driver>,
        value: u64,
    ) -> Result<Self::GpRegisters, VmiError>
    where
        Driver: VmiRead<Architecture = Self::Architecture>,
    {
        // AAPCS64 returns through the link register, so the stack pointer
        // stays unchanged.
        let mut gp = self.gp_registers();
        gp.set_result(value);
        gp.set_instruction_pointer(self.regs[30]);
        Ok(gp)
    }
}

impl<Geometry> vmi_core::arch::EventMemoryAccess for EventMemoryAccess<Geometry>
where
    Geometry: PagingGeometry,
{
    type Architecture = Arm64<Geometry>;

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

impl<Geometry> vmi_core::arch::EventInterrupt for EventInterrupt<Geometry>
where
    Geometry: PagingGeometry,
{
    type Architecture = Arm64<Geometry>;

    fn gfn(&self) -> Gfn {
        self.gfn
    }
}

impl<Geometry> vmi_core::arch::EventReason for EventReason<Geometry>
where
    Geometry: PagingGeometry,
{
    type Architecture = Arm64<Geometry>;

    fn as_memory_access(
        &self,
    ) -> Option<&impl vmi_core::arch::EventMemoryAccess<Architecture = Arm64<Geometry>>> {
        match self {
            EventReason::MemoryAccess(memory_access) => Some(memory_access),
            _ => None,
        }
    }

    fn as_interrupt(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Arm64<Geometry>>> {
        match self {
            EventReason::Interrupt(interrupt) => Some(interrupt),
            _ => None,
        }
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Arm64<Geometry>>> {
        match self {
            EventReason::Interrupt(interrupt) if interrupt.interrupt.is_software_breakpoint() => {
                Some(interrupt)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use vmi_core::{Architecture as _, Pa, Va, arch::Registers as _};

    use crate::{Arm64, Granule4KVa48, Granule16KVa47, PageTableLevel, PagingGeometry, Registers};

    #[test]
    fn page_constants_follow_the_granule() {
        assert_eq!(Arm64::<Granule4KVa48>::PAGE_SIZE, 0x1000);
        assert_eq!(Arm64::<Granule4KVa48>::PAGE_SHIFT, 12);
        assert_eq!(Arm64::<Granule4KVa48>::PAGE_MASK, !0xfff);
        assert_eq!(Arm64::<Granule16KVa47>::PAGE_SIZE, 0x4000);
        assert_eq!(Arm64::<Granule16KVa47>::PAGE_SHIFT, 14);
        assert_eq!(Arm64::<Granule16KVa47>::PAGE_MASK, !0x3fff);
    }

    #[test]
    fn va_helpers_follow_the_geometry() {
        type A = Arm64<Granule16KVa47>;
        let va = Va(0xfffffe002c7e5434);

        assert_eq!(
            A::va_index_for(va, PageTableLevel::L1),
            (va.0 >> 36) & 0x7ff
        );
        assert_eq!(
            A::va_index_for(va, PageTableLevel::L2),
            (va.0 >> 25) & 0x7ff
        );
        assert_eq!(
            A::va_index_for(va, PageTableLevel::L3),
            (va.0 >> 14) & 0x7ff
        );
        assert_eq!(A::va_offset(va), 0x1434);
        assert_eq!(A::va_offset_for(va, PageTableLevel::L2), va.0 & 0x1ff_ffff);
        assert_eq!(A::va_align_down(va), Va(0xfffffe002c7e4000));
        assert_eq!(A::va_align_up(va), Va(0xfffffe002c7e8000));
        assert_eq!(
            A::pa_in_gfn_for(vmi_core::Gfn(0x1d9f9), va, PageTableLevel::L3),
            Pa(0x767e5434)
        );

        type B = Arm64<Granule4KVa48>;
        let va = Va(0x0000_7fff_ffff_f123);
        assert_eq!(B::va_index_for(va, PageTableLevel::L0), 0xff);
        assert_eq!(B::va_offset_for(va, PageTableLevel::L1), va.0 & 0x3fff_ffff);
    }

    #[test]
    fn translation_root_selects_ttbr_by_bit_55() {
        let mut registers = Registers::<Granule16KVa47>::default();
        registers.ttbr0_el1 = 0x004c_0001_e04f_4000;
        registers.ttbr1_el1 = 0x0000_0000_73f8_8001;

        assert_eq!(
            registers.translation_root(Va(0x1_9715_d4b4)),
            Pa(0x1_e04f_4000)
        );
        assert_eq!(
            registers.translation_root(Va(0xffff_fe00_2c7e_5434)),
            Pa(0x73f8_8000)
        );
        // A PAC-signed kernel pointer keeps bit 55 and therefore TTBR1.
        assert_eq!(
            registers.translation_root(Va(0x70e9_7e10_1400_1de0)),
            Pa(0x73f8_8000)
        );
    }

    #[test]
    fn set_translation_root_preserves_asid_and_cnp() {
        let mut registers = Registers::<Granule16KVa47>::default();
        registers.ttbr0_el1 = 0x004c_0001_e04f_4001;
        registers.ttbr1_el1 = 0x0000_0000_73f8_8000;

        registers.set_translation_root(0x1_b03c_4000, Va(0x1_00b2_05a9));
        assert_eq!(registers.ttbr0_el1, 0x004c_0001_b03c_4001);
        assert_eq!(registers.ttbr1_el1, 0x0000_0000_73f8_8000);

        registers.set_translation_root(0x7000_0000, Va(0xffff_fe00_0000_0000));
        assert_eq!(registers.ttbr0_el1, 0x004c_0001_b03c_4001);
        assert_eq!(registers.ttbr1_el1, 0x0000_0000_7000_0000);
    }

    #[test]
    fn stack_pointer_follows_pstate() {
        let mut registers = Registers::<Granule16KVa47>::default();
        registers.sp_el0 = 0x1000;
        registers.sp_el1 = 0x2000;

        // EL1h: EL1 with SP_EL1 selected.
        registers.pstate = 0b0101;
        assert_eq!(registers.stack_pointer(), 0x2000);

        // EL1t: EL1 with SP_EL0 selected.
        registers.pstate = 0b0100;
        assert_eq!(registers.stack_pointer(), 0x1000);

        // EL0t.
        registers.pstate = 0;
        assert_eq!(registers.stack_pointer(), 0x1000);
    }

    #[test]
    fn canonical_address_strips_pac_and_tags() {
        type A = Arm64<Granule16KVa47>;

        assert_eq!(
            A::canonical_address(0x70e9_7e10_1400_1de0),
            Va(0xffff_fe10_1400_1de0)
        );
        assert_eq!(
            A::canonical_address(0x2d0b_8001_9704_46cc),
            Va(0x1_9704_46cc)
        );
        assert_eq!(
            A::canonical_address(0xffff_fe00_2c7e_5434),
            Va(0xffff_fe00_2c7e_5434)
        );
    }

    #[test]
    fn matches_tcr_checks_both_halves() {
        let tcr = 0x8_0022_6511_a511;

        assert!(Granule16KVa47::matches_tcr(tcr));
        assert!(!Granule4KVa48::matches_tcr(tcr));

        // TG0 = 4K, T0SZ = 16, TG1 = 4K, T1SZ = 16.
        let tcr_4k = (0b10 << 30) | (16 << 16) | 16;
        assert!(Granule4KVa48::matches_tcr(tcr_4k));
        assert!(!Granule16KVa47::matches_tcr(tcr_4k));

        // A 16K low half with a mismatched high half does not match.
        let tcr_mixed = (0b10 << 30) | (16 << 16) | (0b10 << 14) | 17;
        assert!(!Granule16KVa47::matches_tcr(tcr_mixed));
    }

    #[test]
    fn software_breakpoint_requires_brk_exception_class() {
        use vmi_core::{Gfn, arch::EventReason as _};

        use crate::{EventInterrupt, EventReason, Interrupt, InterruptType};

        let reason = |interrupt| {
            EventReason::<Granule16KVa47>::Interrupt(EventInterrupt::new(Gfn(0), interrupt))
        };
        let synchronous = |esr| Interrupt {
            typ: InterruptType::Synchronous,
            esr,
            far: 0,
        };

        // BRK #0x1 in AArch64 state.
        let brk = synchronous((0x3c << 26) | (1 << 25) | 1);
        assert!(reason(brk).as_software_breakpoint().is_some());

        // Data abort taken without a change in exception level.
        let data_abort = synchronous((0x25 << 26) | (1 << 25));
        assert!(reason(data_abort).as_software_breakpoint().is_none());

        // SVC #0x80 in AArch64 state.
        let svc = synchronous((0x15 << 26) | (1 << 25) | 0x80);
        assert!(reason(svc).as_software_breakpoint().is_none());

        // An IRQ never is a breakpoint, whatever the syndrome holds.
        let irq = Interrupt {
            typ: InterruptType::Irq,
            ..brk
        };
        assert!(reason(irq).as_software_breakpoint().is_none());
    }
}
