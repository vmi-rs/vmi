use super::{
    Cr0, Cr2, Cr3, Cr4, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Gdtr, Idtr, MsrEfer, Rflags,
    SegmentDescriptor,
};

/// The state of the CPU registers.
#[expect(missing_docs)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: Rflags,

    pub cr0: Cr0,
    pub cr2: Cr2,
    pub cr3: Cr3,
    pub cr4: Cr4,

    pub dr0: Dr0,
    pub dr1: Dr1,
    pub dr2: Dr2,
    pub dr3: Dr3,
    pub dr6: Dr6,
    pub dr7: Dr7,

    pub cs: SegmentDescriptor,
    pub ds: SegmentDescriptor,
    pub es: SegmentDescriptor,
    pub fs: SegmentDescriptor,
    pub gs: SegmentDescriptor,
    pub ss: SegmentDescriptor,
    pub tr: SegmentDescriptor,
    pub ldtr: SegmentDescriptor,

    pub idtr: Idtr,
    pub gdtr: Gdtr,

    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub shadow_gs: u64,

    pub msr_flags: u64,
    pub msr_lstar: u64,
    pub msr_star: u64,
    pub msr_cstar: u64,
    pub msr_syscall_mask: u64,
    pub msr_efer: MsrEfer,
    pub msr_tsc_aux: u64,
    // npt_base: u64,
    // vmtrace_pos: u64,
}

#[expect(missing_docs)]
/// General-purpose registers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GpRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: Rflags,
}
