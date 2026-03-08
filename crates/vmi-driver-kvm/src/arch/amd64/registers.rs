use vmi_arch_amd64::{Gdtr, Idtr, Registers, SegmentDescriptor};

use crate::FromExt;

/// Helper to convert a KVM segment to a `SegmentDescriptor`.
fn segment_from_kvm(seg: &kvm::sys::kvm_vmi_regs__bindgen_ty_1) -> SegmentDescriptor {
    SegmentDescriptor {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector.into(),
        access: (seg.ar as u32).into(),
    }
}

/// Helper to convert a `SegmentDescriptor` to a KVM segment.
fn segment_to_kvm(seg: &SegmentDescriptor) -> kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
    kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector.into(),
        ar: u32::from(seg.access) as u16,
    }
}

impl FromExt<&kvm::sys::kvm_vmi_regs> for Registers {
    fn from_ext(raw: &kvm::sys::kvm_vmi_regs) -> Self {
        Self {
            rax: raw.rax,
            rbx: raw.rbx,
            rcx: raw.rcx,
            rdx: raw.rdx,
            rbp: raw.rbp,
            rsi: raw.rsi,
            rdi: raw.rdi,
            rsp: raw.rsp,
            r8: raw.r8,
            r9: raw.r9,
            r10: raw.r10,
            r11: raw.r11,
            r12: raw.r12,
            r13: raw.r13,
            r14: raw.r14,
            r15: raw.r15,
            rip: raw.rip,
            rflags: raw.rflags.into(),

            cr0: raw.cr0.into(),
            cr2: Default::default(), // not in ring event
            cr3: raw.cr3.into(),
            cr4: raw.cr4.into(),

            dr0: Default::default(), // not in ring event
            dr1: Default::default(),
            dr2: Default::default(),
            dr3: Default::default(),
            dr6: Default::default(),
            dr7: Default::default(),

            cs: segment_from_kvm(&raw.cs),
            ss: segment_from_kvm(&raw.ss),
            ds: segment_from_kvm(&raw.ds),
            es: segment_from_kvm(&raw.es),
            fs: segment_from_kvm(&raw.fs),
            gs: segment_from_kvm(&raw.gs),
            tr: SegmentDescriptor::default(),  // not in ring event
            ldtr: SegmentDescriptor::default(), // not in ring event

            idtr: Idtr::default(), // not in ring event
            gdtr: Gdtr::default(), // not in ring event

            sysenter_cs: raw.sysenter_cs,
            sysenter_esp: raw.sysenter_esp,
            sysenter_eip: raw.sysenter_eip,
            shadow_gs: raw.shadow_gs,

            msr_flags: Default::default(), // not in ring event
            msr_lstar: raw.msr_lstar,
            msr_star: raw.msr_star,
            msr_cstar: raw.msr_cstar,
            msr_syscall_mask: raw.msr_syscall_mask,
            msr_efer: raw.msr_efer.into(),
            msr_tsc_aux: raw.msr_tsc_aux,
        }
    }
}

impl FromExt<&Registers> for kvm::sys::kvm_vmi_regs {
    fn from_ext(regs: &Registers) -> Self {
        Self {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rbp: regs.rbp,
            rsp: regs.rsp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags.into(),

            cr0: regs.cr0.into(),
            cr3: regs.cr3.into(),
            cr4: regs.cr4.into(),
            xcr0: 0, // not in Registers struct as a separate field

            cs: segment_to_kvm(&regs.cs),
            ss: segment_to_kvm(&regs.ss),
            ds: segment_to_kvm(&regs.ds),
            es: segment_to_kvm(&regs.es),
            fs: segment_to_kvm(&regs.fs),
            gs: segment_to_kvm(&regs.gs),

            sysenter_cs: regs.sysenter_cs,
            sysenter_esp: regs.sysenter_esp,
            sysenter_eip: regs.sysenter_eip,
            shadow_gs: regs.shadow_gs,

            msr_star: regs.msr_star,
            msr_lstar: regs.msr_lstar,
            msr_cstar: regs.msr_cstar,
            msr_syscall_mask: regs.msr_syscall_mask,
            msr_efer: regs.msr_efer.into(),
            msr_tsc_aux: regs.msr_tsc_aux,
            msr_kernel_gs_base: 0, // not in Registers struct
        }
    }
}
