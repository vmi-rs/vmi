//! AMD64 architecture definitions.

mod address;
mod cr;
mod descriptor;
mod dr;
mod efer;
mod event;
mod interrupt;
mod paging;
mod registers;
mod rflags;
mod segment;
mod translation;

use vmi_core::{
    AccessContext, AddressContext, Architecture, Gfn, MemoryAccess, Pa, Va, VmiCore, VmiDriver,
    VmiError,
};
use zerocopy::FromBytes;

pub use self::{
    cr::{ControlRegister, Cr0, Cr2, Cr3, Cr4},
    descriptor::{Gdtr, Idtr},
    dr::{Dr0, Dr1, Dr2, Dr3, Dr6, Dr7},
    efer::MsrEfer,
    event::{
        EventCpuId, EventInterrupt, EventIo, EventIoDirection, EventMemoryAccess, EventMonitor,
        EventReason, EventSinglestep, EventWriteControlRegister, MemoryAccessFlags,
    },
    interrupt::{ExceptionVector, Idt, IdtAccess, IdtEntry, Interrupt, InterruptType},
    paging::{PageTableEntry, PageTableLevel, PagingMode},
    registers::{GpRegisters, Registers},
    rflags::Rflags,
    segment::{
        DescriptorTable, DescriptorType, Granularity, OperationSize, SegmentAccess,
        SegmentDescriptor, Selector,
    },
    translation::{TranslationEntries, TranslationEntry, VaTranslation},
};

/// AMD64 architecture.
#[derive(Debug)]
pub struct Amd64;

impl Architecture for Amd64 {
    const PAGE_SIZE: u64 = 0x1000;
    const PAGE_SHIFT: u64 = 12;
    const PAGE_MASK: u64 = 0xFFFFFFFFFFFFF000;

    const BREAKPOINT: &'static [u8] = &[0xcc];

    type Registers = Registers;
    type PageTableLevel = PageTableLevel;
    type Interrupt = Interrupt;
    type SpecialRegister = ControlRegister;

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
        Self::va_align_down_for(va, PageTableLevel::Pt)
    }

    fn va_align_down_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = match level {
            PageTableLevel::Pt => !0xfff,
            PageTableLevel::Pd => !0x1fffff,
            PageTableLevel::Pdpt => !0x3fffffff,
            PageTableLevel::Pml4 => !0x7fffffffff,
        };

        va & mask
    }

    fn va_align_up(va: Va) -> Va {
        Self::va_align_up_for(va, PageTableLevel::Pt)
    }

    fn va_align_up_for(va: Va, level: Self::PageTableLevel) -> Va {
        let mask = match level {
            PageTableLevel::Pt => 0xfff,
            PageTableLevel::Pd => 0x1fffff,
            PageTableLevel::Pdpt => 0x3fffffff,
            PageTableLevel::Pml4 => 0x7fffffffff,
        };

        (va + mask) & !mask
    }

    fn va_offset(va: Va) -> u64 {
        Self::va_offset_for(va, PageTableLevel::Pt)
    }

    fn va_offset_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            // 4KB page (4 * 1024 - 1).
            PageTableLevel::Pt => va.0 & 0xfff,

            // 2MB page (2 * 1024 * 1024 - 1).
            PageTableLevel::Pd => va.0 & 0x1fffff,

            // 1GB page (1024 * 1024 * 1024 - 1).
            PageTableLevel::Pdpt => va.0 & 0x3fffffff,

            // 512GB page (512 * 1024 * 1024 * 1024 - 1).
            PageTableLevel::Pml4 => va.0 & 0x7fffffffff,
        }
    }

    fn va_index(va: Va) -> u64 {
        Self::va_index_for(va, PageTableLevel::Pt)
    }

    fn va_index_for(va: Va, level: Self::PageTableLevel) -> u64 {
        match level {
            PageTableLevel::Pt => (va.0 >> 12) & 0x1ff,
            PageTableLevel::Pd => (va.0 >> 21) & 0x1ff,
            PageTableLevel::Pdpt => (va.0 >> 30) & 0x1ff,
            PageTableLevel::Pml4 => (va.0 >> 39) & 0x1ff,
        }
    }

    fn translate_address<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> Result<Pa, VmiError>
    where
        Driver: VmiDriver<Architecture = Self>,
    {
        // Read the PML4 table
        let buffer = vmi.read_page(Self::gfn_from_pa(root))?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();

        let pml4i = Self::va_index_for(va, PageTableLevel::Pml4) as usize;
        let pml4e = page_table[pml4i];

        if !pml4e.present() {
            return Err(VmiError::page_fault((va, root)));
        }

        if pml4e.large() {
            return Ok(
                Self::pa_from_gfn(pml4e.pfn()) + Self::va_offset_for(va, PageTableLevel::Pml4)
            );
        }

        // Read the PDPT table
        let buffer = vmi.read_page(pml4e.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();

        let pdpti = Self::va_index_for(va, PageTableLevel::Pdpt) as usize;
        let pdpte = page_table[pdpti];

        if !pdpte.present() {
            return Err(VmiError::page_fault((va, root)));
        }

        if pdpte.large() {
            return Ok(
                Self::pa_from_gfn(pdpte.pfn()) + Self::va_offset_for(va, PageTableLevel::Pdpt)
            );
        }

        // Read the PD table
        let buffer = vmi.read_page(pdpte.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();

        let pdi = Self::va_index_for(va, PageTableLevel::Pd) as usize;
        let pde = page_table[pdi];

        if !pde.present() {
            return Err(VmiError::page_fault((va, root)));
        }

        if pde.large() {
            return Ok(Self::pa_from_gfn(pde.pfn()) + Self::va_offset_for(va, PageTableLevel::Pd));
        }

        // Read the PT table
        let buffer = vmi.read_page(pde.pfn())?;
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();

        let pti = Self::va_index_for(va, PageTableLevel::Pt) as usize;
        let pte = page_table[pti];

        if !pte.present() {
            return Err(VmiError::page_fault((va, root)));
        }

        Ok(Self::pa_from_gfn(pte.pfn()) + Self::va_offset_for(va, PageTableLevel::Pt))
    }
}

impl Amd64 {
    /// Canonicalize a virtual address.
    pub fn va_canonical(va: Va) -> Va {
        const BITS: u64 = 48;
        const MASK: u64 = (1 << BITS) - 1;

        Va(va.0 & MASK)
    }

    /// Determine the paging mode of the processor based on control register
    /// values.
    ///
    /// # Paging Modes
    ///
    /// - **No Paging**: When paging is disabled (CR0.PG = 0)
    /// - **32-bit Paging**: Used when CR0.PG = 1 and CR4.PAE = 0
    /// - **PAE Paging**: Used when CR0.PG = 1, CR4.PAE = 1, and IA32_EFER.LME = 0
    /// - **4-level Paging**: Used when CR0.PG = 1, CR4.PAE = 1, IA32_EFER.LME = 1, and CR4.LA57 = 0
    /// - **5-level Paging**: Used when CR0.PG = 1, CR4.PAE = 1, IA32_EFER.LME = 1, and CR4.LA57 = 1
    ///
    /// If paging is disabled, the function returns `None`.
    pub fn paging_mode(registers: &Registers) -> Option<PagingMode> {
        if !registers.cr0.paging() {
            return None;
        }

        if !registers.cr4.physical_address_extension() {
            return Some(PagingMode::Legacy);
        }

        if !registers.msr_efer.long_mode_enable() {
            return Some(PagingMode::PAE);
        }

        if !registers.cr4.linear_address_57_bit() {
            return Some(PagingMode::Ia32e);
        }

        Some(PagingMode::Ia32eLA57)
    }

    /// Retrieves the Interrupt Descriptor Table (IDT) for a specific virtual
    /// CPU.
    pub fn interrupt_descriptor_table<Driver>(
        vmi: &VmiCore<Driver>,
        registers: &Registers,
    ) -> Result<Idt, VmiError>
    where
        Driver: VmiDriver<Architecture = Self>,
    {
        let idtr_base = registers.idtr.base.into();
        vmi.read_struct::<Idt>((idtr_base, registers.cr3.into()))
    }

    /// Performs a page table walk to translate a virtual address to a physical
    /// address.
    ///
    /// This function implements the 4-level paging translation process, walking
    /// through the page tables to convert a virtual address to a physical
    /// address.
    ///
    /// # Process
    ///
    /// 1. Initializes the translation entries vector.
    /// 2. Ensures the virtual address is in canonical form.
    /// 3. Walks through the 4-level paging structure:
    ///    - PML4 (Page Map Level 4)
    ///    - PDPT (Page Directory Pointer Table)
    ///    - PD (Page Directory)
    ///    - PT (Page Table)
    /// 4. At each level:
    ///    - Reads the relevant page table.
    ///    - Extracts the appropriate entry.
    ///    - Checks if the entry is present.
    ///    - Checks if it's a large page (1GB or 2MB).
    ///    - If it's a large page or the last level, calculates the final
    ///      physical address.
    ///    - Otherwise, continues to the next level.
    ///
    /// # Errors
    ///
    /// If any page table read fails, the function returns a [`VaTranslation`]
    /// with the entries collected so far and `None` as the physical
    /// address.
    ///
    /// # Notes
    ///
    /// - This implementation assumes x86-64 4-level paging. It doesn't handle
    ///   5-level paging.
    /// - The function handles large pages (1GB and 2MB) as well as standard 4KB
    ///   pages.
    /// - Each step of the translation is recorded, allowing for detailed
    ///   analysis of the translation process.
    pub fn translation<Driver>(vmi: &VmiCore<Driver>, va: Va, root: Pa) -> VaTranslation
    where
        Driver: VmiDriver<Architecture = Self>,
    {
        let mut entries = TranslationEntries::new();
        let va = Self::va_canonical(va);

        // Read the PML4 table
        let buffer = match vmi.read_page(Self::gfn_from_pa(root)) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let pml4i = Self::va_index_for(va, PageTableLevel::Pml4) as usize;
        let pml4e = page_table[pml4i];

        entries.push(TranslationEntry {
            level: PageTableLevel::Pml4,
            entry: pml4e,
            entry_address: root + (pml4i * size_of::<PageTableEntry>()) as u64,
        });

        if !pml4e.present() {
            return VaTranslation { entries, pa: None };
        }

        if pml4e.large() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(pml4e.pfn()) + Self::va_offset_for(va, PageTableLevel::Pml4),
                ),
            };
        }

        // Read the PDPT table
        let buffer = match vmi.read_page(pml4e.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let pdpti = Self::va_index_for(va, PageTableLevel::Pdpt) as usize;
        let pdpte = page_table[pdpti];

        entries.push(TranslationEntry {
            level: PageTableLevel::Pdpt,
            entry: pdpte,
            entry_address: Self::pa_from_gfn(pml4e.pfn())
                + (pdpti * size_of::<PageTableEntry>()) as u64,
        });

        if !pdpte.present() {
            return VaTranslation { entries, pa: None };
        }

        if pdpte.large() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(pdpte.pfn()) + Self::va_offset_for(va, PageTableLevel::Pdpt),
                ),
            };
        }

        // Read the PD table
        let buffer = match vmi.read_page(pdpte.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let pdi = Self::va_index_for(va, PageTableLevel::Pd) as usize;
        let pde = page_table[pdi];

        entries.push(TranslationEntry {
            level: PageTableLevel::Pd,
            entry: pde,
            entry_address: Self::pa_from_gfn(pdpte.pfn())
                + (pdi * size_of::<PageTableEntry>()) as u64,
        });

        if !pde.present() {
            return VaTranslation { entries, pa: None };
        }

        if pde.large() {
            return VaTranslation {
                entries,
                pa: Some(
                    Self::pa_from_gfn(pde.pfn()) + Self::va_offset_for(va, PageTableLevel::Pd),
                ),
            };
        }

        // Read the PT table
        let buffer = match vmi.read_page(pde.pfn()) {
            Ok(buffer) => buffer,
            Err(_) => return VaTranslation { entries, pa: None },
        };
        let page_table = <[PageTableEntry]>::ref_from_bytes(&buffer).unwrap();
        let pti = Self::va_index_for(va, PageTableLevel::Pt) as usize;
        let pte = page_table[pti];

        entries.push(TranslationEntry {
            level: PageTableLevel::Pt,
            entry: pte,
            entry_address: Self::pa_from_gfn(pde.pfn())
                + (pti * size_of::<PageTableEntry>()) as u64,
        });

        VaTranslation {
            entries,
            pa: Some(Self::pa_from_gfn(pte.pfn()) + Self::va_offset_for(va, PageTableLevel::Pt)),
        }
    }
}

impl vmi_core::arch::Registers for Registers {
    type Architecture = Amd64;

    type GpRegisters = GpRegisters;

    fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    fn set_instruction_pointer(&mut self, ip: u64) {
        self.rip = ip;
    }

    fn stack_pointer(&self) -> u64 {
        self.rsp
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        self.rsp = sp;
    }

    fn result(&self) -> u64 {
        self.rax
    }

    fn set_result(&mut self, result: u64) {
        self.rax = result;
    }

    fn gp_registers(&self) -> GpRegisters {
        GpRegisters {
            rax: self.rax,
            rbx: self.rbx,
            rcx: self.rcx,
            rdx: self.rdx,
            rbp: self.rbp,
            rsi: self.rsi,
            rdi: self.rdi,
            rsp: self.rsp,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            r11: self.r11,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            rip: self.rip,
            rflags: self.rflags,
        }
    }

    fn set_gp_registers(&mut self, gp: &GpRegisters) {
        self.rax = gp.rax;
        self.rbx = gp.rbx;
        self.rcx = gp.rcx;
        self.rdx = gp.rdx;
        self.rbp = gp.rbp;
        self.rsi = gp.rsi;
        self.rdi = gp.rdi;
        self.rsp = gp.rsp;
        self.r8 = gp.r8;
        self.r9 = gp.r9;
        self.r10 = gp.r10;
        self.r11 = gp.r11;
        self.r12 = gp.r12;
        self.r13 = gp.r13;
        self.r14 = gp.r14;
        self.r15 = gp.r15;
        self.rip = gp.rip;
        self.rflags = gp.rflags;
    }

    fn address_width(&self) -> usize {
        Amd64::paging_mode(self).map_or(0, PagingMode::address_width)
    }

    fn effective_address_width(&self) -> usize {
        // IA-32e mode uses a previously unused bit in the CS descriptor.
        // Bit 53 is defined as the 64-bit (L) flag and is used to select
        // between 64-bit mode and compatibility mode when IA-32e mode is
        // active (IA32_EFER.LMA = 1).
        //
        // — If CS.L = 0 and IA-32e mode is active, the processor is running
        //   in compatibility mode. In this case, CS.D selects the default
        //   size for data and addresses. If CS.D = 0, the default data and
        //   address size is 16 bits. If CS.D = 1, the default data and address
        //   size is 32 bits.
        //
        // — If CS.L = 1 and IA-32e mode is active, the only valid setting
        //   is CS.D = 0. This setting indicates a default operand size of
        //   32 bits and a default address size of 64 bits. The CS.L = 1 and
        //   CS.D = 1 bit combination is reserved for future use and a #GP
        //   fault will be generated on an attempt to use a code segment
        //   with these bits set in IA-32e mode.
        //
        // [Intel SDM Vol. 3A 5.2.1 (Code-Segment Descriptor in 64-bit Mode)]

        match Amd64::paging_mode(self) {
            Some(PagingMode::Ia32e | PagingMode::Ia32eLA57) if !self.cs.access.long_mode() => 4,
            Some(paging_mode) => paging_mode.address_width(),
            _ => 0,
        }
    }

    fn access_context(&self, va: Va) -> AccessContext {
        self.address_context(va).into()
    }

    fn address_context(&self, va: Va) -> AddressContext {
        (va, self.cr3.into()).into()
    }

    fn translation_root(&self, _va: Va) -> Pa {
        self.cr3.into()
    }

    fn return_address<Driver>(&self, vmi: &VmiCore<Driver>) -> Result<Va, VmiError>
    where
        Driver: VmiDriver,
    {
        vmi.read_va(
            (self.rsp.into(), self.cr3.into()),
            self.effective_address_width(),
        )
    }
}

impl vmi_core::arch::EventMemoryAccess for EventMemoryAccess {
    type Architecture = Amd64;

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
    type Architecture = Amd64;

    fn gfn(&self) -> Gfn {
        self.gfn
    }
}

impl vmi_core::arch::EventReason for EventReason {
    type Architecture = Amd64;

    fn as_memory_access(
        &self,
    ) -> Option<&impl vmi_core::arch::EventMemoryAccess<Architecture = Amd64>> {
        match self {
            EventReason::MemoryAccess(memory_access) => Some(memory_access),
            _ => None,
        }
    }

    fn as_interrupt(&self) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Amd64>> {
        match self {
            EventReason::Interrupt(interrupt) => Some(interrupt),
            _ => None,
        }
    }

    fn as_software_breakpoint(
        &self,
    ) -> Option<&impl vmi_core::arch::EventInterrupt<Architecture = Amd64>> {
        match self {
            EventReason::Interrupt(interrupt)
                if interrupt.interrupt.vector == ExceptionVector::Breakpoint
                    && interrupt.interrupt.typ == InterruptType::SoftwareException =>
            {
                Some(interrupt)
            }
            _ => None,
        }
    }
}
