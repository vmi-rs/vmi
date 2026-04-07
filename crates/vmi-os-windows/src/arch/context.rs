use vmi_arch_amd64::{
    Cr0, Cr2, Cr3, Cr4, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Gdtr, Idtr, Registers, Rflags, Selector,
};
use zerocopy::{FromBytes, IntoBytes};

macro_rules! static_assert_eq {
    ($a:expr, $b:expr) => {
        const _: () = [(); 1][($a == $b) as usize ^ 1];
    };
}

#[allow(missing_docs)]
pub const SIZE_OF_80387_REGISTERS: usize = 80;
#[allow(missing_docs)]
pub const MAXIMUM_SUPPORTED_EXTENSION: usize = 512;

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; SIZE_OF_80387_REGISTERS],
    pub Spare0: u32,
}

static_assert_eq!(size_of::<FLOATING_SAVE_AREA>(), 112);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct CONTEXT_X86 {
    pub ContextFlags: u32,

    pub Dr7: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,

    pub FloatSave: FLOATING_SAVE_AREA,

    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,

    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,

    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,

    pub ExtendedRegisters: [u8; MAXIMUM_SUPPORTED_EXTENSION],
}

static_assert_eq!(size_of::<CONTEXT_X86>(), 716);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

static_assert_eq!(size_of::<XSAVE_FORMAT>(), 512);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct CONTEXT_AMD64 {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,

    pub ContextFlags: u32,
    pub MxCsr: u32,

    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,

    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,

    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,

    pub Rip: u64,

    // union {
    pub FltSave: XSAVE_FORMAT,

    //   struct {
    //     Header: [M128A; 2],
    //     Legacy: [M128A; 8],
    //     Xmm0: M128A,
    //     Xmm1: M128A,
    //     Xmm2: M128A,
    //     Xmm3: M128A,
    //     Xmm4: M128A,
    //     Xmm5: M128A,
    //     Xmm6: M128A,
    //     Xmm7: M128A,
    //     Xmm8: M128A,
    //     Xmm9: M128A,
    //     Xmm10: M128A,
    //     Xmm11: M128A,
    //     Xmm12: M128A,
    //     Xmm13: M128A,
    //     Xmm14: M128A,
    //     Xmm15: M128A,
    //   }
    // }
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,

    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

static_assert_eq!(size_of::<CONTEXT_AMD64>(), 1232);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct KDESCRIPTOR_X86 {
    pub Pad: u16,
    pub Limit: u16,
    pub Base: u32,
}

static_assert_eq!(size_of::<KDESCRIPTOR_X86>(), 8);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct KSPECIAL_REGISTERS_X86 {
    pub Cr0: u32,
    pub Cr2: u32,
    pub Cr3: u32,
    pub Cr4: u32,
    pub KernelDr0: u32,
    pub KernelDr1: u32,
    pub KernelDr2: u32,
    pub KernelDr3: u32,
    pub KernelDr6: u32,
    pub KernelDr7: u32,
    pub Gdtr: KDESCRIPTOR_X86,
    pub Idtr: KDESCRIPTOR_X86,
    pub Tr: u16,
    pub Ldtr: u16,
    pub Reserved: [u32; 6],
}

static_assert_eq!(size_of::<KSPECIAL_REGISTERS_X86>(), 84);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct KDESCRIPTOR_AMD64 {
    pub Pad: [u16; 3],
    pub Limit: u16,
    pub Base: u64,
}

static_assert_eq!(size_of::<KDESCRIPTOR_AMD64>(), 16);

#[allow(missing_docs, non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct KSPECIAL_REGISTERS_AMD64 {
    pub Cr0: u64,
    pub Cr2: u64,
    pub Cr3: u64,
    pub Cr4: u64,
    pub KernelDr0: u64,
    pub KernelDr1: u64,
    pub KernelDr2: u64,
    pub KernelDr3: u64,
    pub KernelDr6: u64,
    pub KernelDr7: u64,
    pub Gdtr: KDESCRIPTOR_AMD64,
    pub Idtr: KDESCRIPTOR_AMD64,
    pub Tr: u16,
    pub Ldtr: u16,
    pub MxCsr: u32,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
    pub Cr8: u64,
    pub MsrGsBase: u64,
    pub MsrGsSwap: u64,
    pub MsrStar: u64,
    pub MsrLStar: u64,
    pub MsrCStar: u64,
    pub MsrSyscallMask: u64,
    //* 0x00d8 */ Xcr0: u64,
    //* 0x00e0 */ MsrFsBase: u64,
    //* 0x00e8 */ SpecialPadding0: u64,
}

static_assert_eq!(size_of::<KSPECIAL_REGISTERS_AMD64>(), 216);

/// Accessor trait for Windows special registers (control, debug, descriptor tables).
///
/// Corresponds to fields of `_KSPECIAL_REGISTERS`.
#[allow(missing_docs)]
pub trait WindowsSpecialRegisters {
    fn cr0(&self) -> Cr0;
    fn cr2(&self) -> Cr2;
    fn cr3(&self) -> Cr3;
    fn cr4(&self) -> Cr4;
    fn kernel_dr0(&self) -> Dr0;
    fn kernel_dr1(&self) -> Dr1;
    fn kernel_dr2(&self) -> Dr2;
    fn kernel_dr3(&self) -> Dr3;
    fn kernel_dr6(&self) -> Dr6;
    fn kernel_dr7(&self) -> Dr7;
    fn gdtr(&self) -> Gdtr;
    fn idtr(&self) -> Idtr;
    fn tr(&self) -> Selector;
    fn ldtr(&self) -> Selector;

    fn msr_gs_base(&self) -> Option<u64> {
        None
    }

    fn msr_gs_swap(&self) -> Option<u64> {
        None
    }

    fn msr_star(&self) -> Option<u64> {
        None
    }

    fn msr_lstar(&self) -> Option<u64> {
        None
    }

    fn msr_cstar(&self) -> Option<u64> {
        None
    }

    fn msr_syscall_mask(&self) -> Option<u64> {
        None
    }
}

impl WindowsSpecialRegisters for KSPECIAL_REGISTERS_X86 {
    fn cr0(&self) -> Cr0 {
        Cr0(self.Cr0 as u64)
    }

    fn cr2(&self) -> Cr2 {
        Cr2(self.Cr2 as u64)
    }

    fn cr3(&self) -> Cr3 {
        Cr3(self.Cr3 as u64)
    }

    fn cr4(&self) -> Cr4 {
        Cr4(self.Cr4 as u64)
    }

    fn kernel_dr0(&self) -> Dr0 {
        Dr0(self.KernelDr0 as u64)
    }

    fn kernel_dr1(&self) -> Dr1 {
        Dr1(self.KernelDr1 as u64)
    }

    fn kernel_dr2(&self) -> Dr2 {
        Dr2(self.KernelDr2 as u64)
    }

    fn kernel_dr3(&self) -> Dr3 {
        Dr3(self.KernelDr3 as u64)
    }

    fn kernel_dr6(&self) -> Dr6 {
        Dr6(self.KernelDr6 as u64)
    }

    fn kernel_dr7(&self) -> Dr7 {
        Dr7(self.KernelDr7 as u64)
    }

    fn gdtr(&self) -> Gdtr {
        Gdtr {
            limit: self.Gdtr.Limit as u32,
            base: self.Gdtr.Base as u64,
        }
    }

    fn idtr(&self) -> Idtr {
        Idtr {
            limit: self.Idtr.Limit as u32,
            base: self.Idtr.Base as u64,
        }
    }

    fn tr(&self) -> Selector {
        Selector(self.Tr)
    }

    fn ldtr(&self) -> Selector {
        Selector(self.Ldtr)
    }
}

impl WindowsSpecialRegisters for KSPECIAL_REGISTERS_AMD64 {
    fn cr0(&self) -> Cr0 {
        Cr0(self.Cr0)
    }

    fn cr2(&self) -> Cr2 {
        Cr2(self.Cr2)
    }

    fn cr3(&self) -> Cr3 {
        Cr3(self.Cr3)
    }

    fn cr4(&self) -> Cr4 {
        Cr4(self.Cr4)
    }

    fn kernel_dr0(&self) -> Dr0 {
        Dr0(self.KernelDr0)
    }

    fn kernel_dr1(&self) -> Dr1 {
        Dr1(self.KernelDr1)
    }

    fn kernel_dr2(&self) -> Dr2 {
        Dr2(self.KernelDr2)
    }

    fn kernel_dr3(&self) -> Dr3 {
        Dr3(self.KernelDr3)
    }

    fn kernel_dr6(&self) -> Dr6 {
        Dr6(self.KernelDr6)
    }

    fn kernel_dr7(&self) -> Dr7 {
        Dr7(self.KernelDr7)
    }

    fn gdtr(&self) -> Gdtr {
        Gdtr {
            limit: self.Gdtr.Limit as u32,
            base: self.Gdtr.Base,
        }
    }

    fn idtr(&self) -> Idtr {
        Idtr {
            limit: self.Idtr.Limit as u32,
            base: self.Idtr.Base,
        }
    }

    fn tr(&self) -> Selector {
        Selector(self.Tr)
    }

    fn ldtr(&self) -> Selector {
        Selector(self.Ldtr)
    }

    fn msr_gs_base(&self) -> Option<u64> {
        Some(self.MsrGsBase)
    }

    fn msr_gs_swap(&self) -> Option<u64> {
        Some(self.MsrGsSwap)
    }

    fn msr_star(&self) -> Option<u64> {
        Some(self.MsrStar)
    }

    fn msr_lstar(&self) -> Option<u64> {
        Some(self.MsrLStar)
    }

    fn msr_cstar(&self) -> Option<u64> {
        Some(self.MsrCStar)
    }

    fn msr_syscall_mask(&self) -> Option<u64> {
        Some(self.MsrSyscallMask)
    }
}

/// Accessor trait for a Windows thread context (general-purpose registers, flags, segments).
///
/// Corresponds to fields of `_CONTEXT`.
#[allow(missing_docs)]
pub trait WindowsContext {
    fn rax(&self) -> u64;
    fn rbx(&self) -> u64;
    fn rcx(&self) -> u64;
    fn rdx(&self) -> u64;
    fn rbp(&self) -> u64;
    fn rsi(&self) -> u64;
    fn rdi(&self) -> u64;
    fn rsp(&self) -> u64;

    fn r8(&self) -> Option<u64> {
        None
    }

    fn r9(&self) -> Option<u64> {
        None
    }

    fn r10(&self) -> Option<u64> {
        None
    }

    fn r11(&self) -> Option<u64> {
        None
    }

    fn r12(&self) -> Option<u64> {
        None
    }

    fn r13(&self) -> Option<u64> {
        None
    }

    fn r14(&self) -> Option<u64> {
        None
    }

    fn r15(&self) -> Option<u64> {
        None
    }

    fn rip(&self) -> u64;
    fn rflags(&self) -> Rflags;

    fn dr0(&self) -> Dr0;
    fn dr1(&self) -> Dr1;
    fn dr2(&self) -> Dr2;
    fn dr3(&self) -> Dr3;
    fn dr6(&self) -> Dr6;
    fn dr7(&self) -> Dr7;

    fn seg_cs(&self) -> Selector;
    fn seg_ds(&self) -> Selector;
    fn seg_es(&self) -> Selector;
    fn seg_fs(&self) -> Selector;
    fn seg_gs(&self) -> Selector;
    fn seg_ss(&self) -> Selector;
}

impl WindowsContext for CONTEXT_X86 {
    fn rax(&self) -> u64 {
        self.Eax as u64
    }

    fn rbx(&self) -> u64 {
        self.Ebx as u64
    }

    fn rcx(&self) -> u64 {
        self.Ecx as u64
    }

    fn rdx(&self) -> u64 {
        self.Edx as u64
    }

    fn rbp(&self) -> u64 {
        self.Ebp as u64
    }

    fn rsi(&self) -> u64 {
        self.Esi as u64
    }

    fn rdi(&self) -> u64 {
        self.Edi as u64
    }

    fn rsp(&self) -> u64 {
        self.Esp as u64
    }

    fn rip(&self) -> u64 {
        self.Eip as u64
    }

    fn rflags(&self) -> Rflags {
        Rflags(self.EFlags as u64)
    }

    fn dr0(&self) -> Dr0 {
        Dr0(self.Dr0 as u64)
    }

    fn dr1(&self) -> Dr1 {
        Dr1(self.Dr1 as u64)
    }

    fn dr2(&self) -> Dr2 {
        Dr2(self.Dr2 as u64)
    }

    fn dr3(&self) -> Dr3 {
        Dr3(self.Dr3 as u64)
    }

    fn dr6(&self) -> Dr6 {
        Dr6(self.Dr6 as u64)
    }

    fn dr7(&self) -> Dr7 {
        Dr7(self.Dr7 as u64)
    }

    fn seg_cs(&self) -> Selector {
        Selector(self.SegCs as u16)
    }

    fn seg_ds(&self) -> Selector {
        Selector(self.SegDs as u16)
    }

    fn seg_es(&self) -> Selector {
        Selector(self.SegEs as u16)
    }

    fn seg_fs(&self) -> Selector {
        Selector(self.SegFs as u16)
    }

    fn seg_gs(&self) -> Selector {
        Selector(self.SegGs as u16)
    }

    fn seg_ss(&self) -> Selector {
        Selector(self.SegSs as u16)
    }
}

impl WindowsContext for CONTEXT_AMD64 {
    fn rax(&self) -> u64 {
        self.Rax
    }

    fn rbx(&self) -> u64 {
        self.Rbx
    }

    fn rcx(&self) -> u64 {
        self.Rcx
    }

    fn rdx(&self) -> u64 {
        self.Rdx
    }

    fn rbp(&self) -> u64 {
        self.Rbp
    }

    fn rsi(&self) -> u64 {
        self.Rsi
    }

    fn rdi(&self) -> u64 {
        self.Rdi
    }

    fn rsp(&self) -> u64 {
        self.Rsp
    }

    fn r8(&self) -> Option<u64> {
        Some(self.R8)
    }

    fn r9(&self) -> Option<u64> {
        Some(self.R9)
    }

    fn r10(&self) -> Option<u64> {
        Some(self.R10)
    }

    fn r11(&self) -> Option<u64> {
        Some(self.R11)
    }

    fn r12(&self) -> Option<u64> {
        Some(self.R12)
    }

    fn r13(&self) -> Option<u64> {
        Some(self.R13)
    }

    fn r14(&self) -> Option<u64> {
        Some(self.R14)
    }

    fn r15(&self) -> Option<u64> {
        Some(self.R15)
    }

    fn rip(&self) -> u64 {
        self.Rip
    }

    fn rflags(&self) -> Rflags {
        Rflags(self.EFlags as u64)
    }

    fn dr0(&self) -> Dr0 {
        Dr0(self.Dr0)
    }

    fn dr1(&self) -> Dr1 {
        Dr1(self.Dr1)
    }

    fn dr2(&self) -> Dr2 {
        Dr2(self.Dr2)
    }

    fn dr3(&self) -> Dr3 {
        Dr3(self.Dr3)
    }

    fn dr6(&self) -> Dr6 {
        Dr6(self.Dr6)
    }

    fn dr7(&self) -> Dr7 {
        Dr7(self.Dr7)
    }

    fn seg_cs(&self) -> Selector {
        Selector(self.SegCs)
    }

    fn seg_ds(&self) -> Selector {
        Selector(self.SegDs)
    }

    fn seg_es(&self) -> Selector {
        Selector(self.SegEs)
    }

    fn seg_fs(&self) -> Selector {
        Selector(self.SegFs)
    }

    fn seg_gs(&self) -> Selector {
        Selector(self.SegGs)
    }

    fn seg_ss(&self) -> Selector {
        Selector(self.SegSs)
    }
}

/// Adapter for writing Windows context and special registers into VMI register state.
pub trait WindowsRegistersAdapter {
    /// Writes general-purpose registers, instruction pointer, flags, and segment selectors.
    fn write_context(&mut self, context: &impl WindowsContext);

    /// Writes control registers, debug registers, and descriptor tables.
    fn write_special_registers(&mut self, special_registers: &impl WindowsSpecialRegisters);
}

impl WindowsRegistersAdapter for Registers {
    fn write_context(&mut self, context: &impl WindowsContext) {
        self.rax = context.rax();
        self.rbx = context.rbx();
        self.rcx = context.rcx();
        self.rdx = context.rdx();
        self.rbp = context.rbp();
        self.rsi = context.rsi();
        self.rdi = context.rdi();
        self.rsp = context.rsp();
        if let Some(r8) = context.r8() {
            self.r8 = r8;
        }
        if let Some(r9) = context.r9() {
            self.r9 = r9;
        }
        if let Some(r10) = context.r10() {
            self.r10 = r10;
        }
        if let Some(r11) = context.r11() {
            self.r11 = r11;
        }
        if let Some(r12) = context.r12() {
            self.r12 = r12;
        }
        if let Some(r13) = context.r13() {
            self.r13 = r13;
        }
        if let Some(r14) = context.r14() {
            self.r14 = r14;
        }
        if let Some(r15) = context.r15() {
            self.r15 = r15;
        }
        self.rip = context.rip();
        self.rflags = context.rflags();

        self.dr0 = context.dr0();
        self.dr1 = context.dr1();
        self.dr2 = context.dr2();
        self.dr3 = context.dr3();
        self.dr6 = context.dr6();
        self.dr7 = context.dr7();

        self.cs.selector = context.seg_cs();
        self.ds.selector = context.seg_ds();
        self.es.selector = context.seg_es();
        self.fs.selector = context.seg_fs();
        self.gs.selector = context.seg_gs();
        self.ss.selector = context.seg_ss();
    }

    fn write_special_registers(&mut self, special_registers: &impl WindowsSpecialRegisters) {
        self.cr0 = special_registers.cr0();
        self.cr2 = special_registers.cr2();
        self.cr3 = special_registers.cr3();
        self.cr4 = special_registers.cr4();
        self.dr0 = special_registers.kernel_dr0();
        self.dr1 = special_registers.kernel_dr1();
        self.dr2 = special_registers.kernel_dr2();
        self.dr3 = special_registers.kernel_dr3();
        self.dr6 = special_registers.kernel_dr6();
        self.dr7 = special_registers.kernel_dr7();

        let gdtr = special_registers.gdtr();
        self.gdtr.limit = gdtr.limit;
        self.gdtr.base = gdtr.base;

        let idtr = special_registers.idtr();
        self.idtr.limit = idtr.limit;
        self.idtr.base = idtr.base;

        self.tr.selector = special_registers.tr();
        self.ldtr.selector = special_registers.ldtr();

        // if let Some(msr_gs_base) = special_registers.msr_gs_base() {
        // }
        //
        // if let Some(msr_gs_swap) = special_registers.msr_gs_swap() {
        // }

        if let Some(msr_star) = special_registers.msr_star() {
            self.msr_star = msr_star;
        }

        if let Some(msr_lstar) = special_registers.msr_lstar() {
            self.msr_lstar = msr_lstar;
        }

        if let Some(msr_cstar) = special_registers.msr_cstar() {
            self.msr_cstar = msr_cstar;
        }

        if let Some(msr_syscall_mask) = special_registers.msr_syscall_mask() {
            self.msr_syscall_mask = msr_syscall_mask;
        }
    }
}
