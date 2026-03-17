//! AArch64 architecture definitions.

mod address;
mod event;
mod interrupt;
mod paging;
mod registers;
mod translation;

use vmi_core::{
    AccessContext, AddressContext, Architecture, Gfn, MemoryAccess, Pa, Va, VmiCore, VmiError,
    driver::VmiRead,
};
use zerocopy::FromBytes;

pub use self::{
    address::{ttbr_to_gfn, ttbr_to_pa},
    event::{
        EventBreakpoint, EventMemoryAccess, EventMonitor, EventReason, EventSinglestep,
        EventSysreg, SystemRegister,
    },
    interrupt::{Interrupt, SyncException},
    paging::{PageTableEntry, PageTableLevel},
    registers::{GpRegisters, Pstate, Registers},
    translation::{TranslationEntries, TranslationEntry, VaTranslation},
};

/// AArch64 architecture.
#[derive(Debug)]
pub struct Aarch64;

impl Architecture for Aarch64 {
    const PAGE_SIZE: u64 = 0x1000;
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xFFFF_FFFF_FFFF_F000;

    // BRK #0 = 0xD4200000 in little-endian.
    const BREAKPOINT: &'static [u8] = &[0x00, 0x00, 0x20, 0xD4];

    type Registers = Registers;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = SystemRegister;

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
        let mask = match level {
            PageTableLevel::L3 => !0xFFFu64,
            PageTableLevel::L2 => !0x1F_FFFFu64,
            PageTableLevel::L1 => !0x3FFF_FFFFu64,
            PageTableLevel::L0 => !0x7F_FFFF_FFFFu64,
        };

        va & mask
    }

    fn va_align_up(va: Va) -> Va {
        Self::va_align_up_for(va, PageTableLevel::L3)
    }

    fn va_align_up_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = match level {
            PageTableLevel::L3 => 0xFFF,
            PageTableLevel::L2 => 0x1F_FFFF,
            PageTableLevel::L1 => 0x3FFF_FFFF,
            PageTableLevel::L0 => 0x7F_FFFF_FFFF,
        };

        (va + mask) & !mask
    }

    fn va_offset(va: Va) -> u64 {
        Self::va_offset_for(va, PageTableLevel::L3)
    }

    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            PageTableLevel::L3 => va.0 & 0xFFF,
            PageTableLevel::L2 => va.0 & 0x1F_FFFF,
            PageTableLevel::L1 => va.0 & 0x3FFF_FFFF,
            PageTableLevel::L0 => va.0 & 0x7F_FFFF_FFFF,
        }
    }

    fn va_index(va: Va) -> u64 {
        Self::va_index_for(va, PageTableLevel::L3)
    }

    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            PageTableLevel::L3 => (va.0 >> 12) & 0x1FF,
            PageTableLevel::L2 => (va.0 >> 21) & 0x1FF,
            PageTableLevel::L1 => (va.0 >> 30) & 0x1FF,
            PageTableLevel::L0 => (va.0 >> 39) & 0x1FF,
        }
    }

    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiRead<Architecture = Self>,
    {
        // L0 (PGD)
        let buffer = vmi.read_page(Self::gfn_from_pa(root))?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l0i = Self::va_index_for(va, PageTableLevel::L0) as usize;
        let l0e = page_table[l0i];

        if !l0e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }
        // L0 cannot be a block descriptor with 4KB granule.

        // L1 (PUD)
        let buffer = vmi.read_page(l0e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l1i = Self::va_index_for(va, PageTableLevel::L1) as usize;
        let l1e = page_table[l1i];

        if !l1e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }

        if l1e.is_block() {
            return Ok(
                Self::pa_from_gfn(l1e.pfn()) + Self::va_offset_for(va, PageTableLevel::L1)
            );
        }

        // L2 (PMD)
        let buffer = vmi.read_page(l1e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l2i = Self::va_index_for(va, PageTableLevel::L2) as usize;
        let l2e = page_table[l2i];

        if !l2e.valid() {
            return Err(VmiError::page_fault((va, root)));
        }

        if l2e.is_block() {
            return Ok(
                Self::pa_from_gfn(l2e.pfn()) + Self::va_offset_for(va, PageTableLevel::L2)
            );
        }

        // L3 (PTE)
        let buffer = vmi.read_page(l2e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l3i = Self::va_index_for(va, PageTableLevel::L3) as usize;
        let l3e = page_table[l3i];

        if !l3e.valid() || !l3e.is_page() {
            return Err(VmiError::page_fault((va, root)));
        }

        Ok(Self::pa_from_gfn(l3e.pfn()) + Self::va_offset_for(va, PageTableLevel::L3))
    }
}

impl Aarch64 {
    /// Performs a detailed page table walk returning all intermediate entries.
    pub fn translation<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> VaTranslation
    where
        Driver: VmiRead<Architecture = Self>,
    {
        let mut entries = TranslationEntries::new();

        // L0 (PGD)
        let buffer = match vmi.read_page(Self::gfn_from_pa(root)) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l0i = Self::va_index_for(va, PageTableLevel::L0) as usize;
        let l0e = page_table[l0i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L0,
            entry: l0e,
            entry_address: root + (l0i * size_of::<PageTableEntry>()) as u64,
        });

        if !l0e.valid() {
            return VaTranslation { entries, pa: None };
        }

        // L1 (PUD)
        let buffer = match vmi.read_page(l0e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l1i = Self::va_index_for(va, PageTableLevel::L1) as usize;
        let l1e = page_table[l1i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L1,
            entry: l1e,
            entry_address: Self::pa_from_gfn(l0e.pfn())
                + (l1i * size_of::<PageTableEntry>()) as u64,
        });

        if !l1e.valid() {
            return VaTranslation { entries, pa: None };
        }

        if l1e.is_block() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(l1e.pfn()) + Self::va_offset_for(va, PageTableLevel::L1),
                ),
            };
        }

        // L2 (PMD)
        let buffer = match vmi.read_page(l1e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l2i = Self::va_index_for(va, PageTableLevel::L2) as usize;
        let l2e = page_table[l2i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L2,
            entry: l2e,
            entry_address: Self::pa_from_gfn(l1e.pfn())
                + (l2i * size_of::<PageTableEntry>()) as u64,
        });

        if !l2e.valid() {
            return VaTranslation { entries, pa: None };
        }

        if l2e.is_block() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(l2e.pfn()) + Self::va_offset_for(va, PageTableLevel::L2),
                ),
            };
        }

        // L3 (PTE)
        let buffer = match vmi.read_page(l2e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let l3i = Self::va_index_for(va, PageTableLevel::L3) as usize;
        let l3e = page_table[l3i];

        entries.push(TranslationEntry {
            level: PageTableLevel::L3,
            entry: l3e,
            entry_address: Self::pa_from_gfn(l2e.pfn())
                + (l3i * size_of::<PageTableEntry>()) as u64,
        });

        VaTranslation {
            entries,
            pa: if l3e.valid() && l3e.is_page() {
                Some(Self::pa_from_gfn(l3e.pfn()) + Self::va_offset_for(va, PageTableLevel::L3))
            } else {
                None
            },
        }
    }
}

impl vmi_core::arch::GpRegisters for GpRegisters {}

impl vmi_core::arch::Registers for Registers {
    type Architecture = Aarch64;

    type GpRegisters = GpRegisters;

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
        self.x[0]
    }

    fn set_result(&mut self, result: u64) {
        self.x[0] = result;
    }

    fn gp_registers(&self) -> GpRegisters {
        GpRegisters {
            x: self.x,
            sp: self.sp,
            pc: self.pc,
            pstate: self.pstate,
        }
    }

    fn set_gp_registers(&mut self, gp: &GpRegisters) {
        self.x = gp.x;
        self.sp = gp.sp;
        self.pc = gp.pc;
        self.pstate = gp.pstate;
    }

    fn address_width(&self) -> usize {
        8 // AArch64 is always 64-bit
    }

    fn effective_address_width(&self) -> usize {
        8 // AArch64 is always 64-bit
    }

    fn access_context(&self, va: Va) -> AccessContext {
        self.address_context(va).into()
    }

    fn address_context(&self, va: Va) -> AddressContext {
        (va, self.translation_root(va)).into()
    }

    fn translation_root(&self, va: Va) -> Pa {
        // Bit 55 selects TTBR: 1 = TTBR1 (kernel), 0 = TTBR0 (user).
        let ttbr = if va.0 & (1 << 55) != 0 {
            self.ttbr1_el1
        } else {
            self.ttbr0_el1
        };
        ttbr_to_pa(ttbr)
    }

    fn return_address<Driver>(&self, _vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiRead,
    {
        // ARM64 link register is x30.
        // Known limitation: non-leaf functions may have saved LR to stack.
        Ok(Va(self.x[30]))
    }
}

impl vmi_core::arch::EventMemoryAccess for EventMemoryAccess {
    type Architecture = Aarch64;

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

impl vmi_core::arch::EventInterrupt for EventBreakpoint {
    type Architecture = Aarch64;

    fn gfn(&self) -> Gfn {
        self.gfn
    }
}

impl vmi_core::arch::EventReason for EventReason {
    type Architecture = Aarch64;

    fn as_memory_access(
        &self,
    ) -> Option<&impl vmi_core::arch::EventMemoryAccess<Architecture = Aarch64>> {
        match self {
            EventReason::MemoryAccess(memory_access) => Some(memory_access),
            _ => None,
        }
    }

    fn as_interrupt(&self) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Aarch64>> {
        match self {
            EventReason::Breakpoint(breakpoint) => Some(breakpoint),
            _ => None,
        }
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Aarch64>> {
        match self {
            EventReason::Breakpoint(breakpoint) => Some(breakpoint),
            _ => None,
        }
    }
}
