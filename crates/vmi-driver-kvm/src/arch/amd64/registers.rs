use vmi_arch_amd64::{Gdtr, Idtr, Registers, SegmentDescriptor};

use crate::FromExt;

/// Convert a standard `kvm_segment` (from KVM_GET_SREGS) to a `SegmentDescriptor`.
///
/// The `kvm_segment` has separate fields (type, s, dpl, present, avl, l, db, g, unusable).
/// We pack them into the compact access-rights format used by `SegmentAccess`:
///   bits 0-3: type, bit 4: S, bits 5-6: DPL, bit 7: P,
///   bit 8: AVL, bit 9: L, bit 10: D/B, bit 11: G, bit 12: unusable
fn segment_from_kvm_std(seg: &kvm::sys::kvm_segment) -> SegmentDescriptor {
    let ar: u32 = (seg.type_ as u32)
        | ((seg.s as u32) << 4)
        | ((seg.dpl as u32) << 5)
        | ((seg.present as u32) << 7)
        | ((seg.avl as u32) << 8)
        | ((seg.l as u32) << 9)
        | ((seg.db as u32) << 10)
        | ((seg.g as u32) << 11)
        | ((seg.unusable as u32) << 12);

    SegmentDescriptor {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector.into(),
        access: ar.into(),
    }
}

/// Convert a `kvm_dtable` (from KVM_GET_SREGS) to an `Idtr`.
fn idtr_from_kvm_std(dt: &kvm::sys::kvm_dtable) -> Idtr {
    Idtr {
        base: dt.base,
        limit: dt.limit as u32,
    }
}

/// Convert a `kvm_dtable` (from KVM_GET_SREGS) to a `Gdtr`.
fn gdtr_from_kvm_std(dt: &kvm::sys::kvm_dtable) -> Gdtr {
    Gdtr {
        base: dt.base,
        limit: dt.limit as u32,
    }
}

/// Build full `Registers` from `kvm_regs` + `kvm_sregs` + MSR values.
///
/// This is used when reading registers via KVM_GET_REGS/SREGS/MSRS ioctls
/// on a vCPU fd (outside of ring events).
pub(crate) fn registers_from_kvm(
    regs: &kvm::sys::kvm_regs,
    sregs: &kvm::sys::kvm_sregs,
    msrs: &kvm::MsrValues,
) -> Registers {
    Registers {
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rbp: regs.rbp,
        rsi: regs.rsi,
        rdi: regs.rdi,
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

        cr0: sregs.cr0.into(),
        cr2: sregs.cr2.into(),
        cr3: sregs.cr3.into(),
        cr4: sregs.cr4.into(),

        dr0: Default::default(),
        dr1: Default::default(),
        dr2: Default::default(),
        dr3: Default::default(),
        dr6: Default::default(),
        dr7: Default::default(),

        cs: segment_from_kvm_std(&sregs.cs),
        ss: segment_from_kvm_std(&sregs.ss),
        ds: segment_from_kvm_std(&sregs.ds),
        es: segment_from_kvm_std(&sregs.es),
        fs: segment_from_kvm_std(&sregs.fs),
        gs: segment_from_kvm_std(&sregs.gs),
        tr: segment_from_kvm_std(&sregs.tr),
        ldtr: segment_from_kvm_std(&sregs.ldt),

        idtr: idtr_from_kvm_std(&sregs.idt),
        gdtr: gdtr_from_kvm_std(&sregs.gdt),

        sysenter_cs: msrs.sysenter_cs,
        sysenter_esp: msrs.sysenter_esp,
        sysenter_eip: msrs.sysenter_eip,
        shadow_gs: msrs.kernel_gs_base,

        msr_flags: Default::default(),
        msr_lstar: msrs.lstar,
        msr_star: msrs.star,
        msr_cstar: msrs.cstar,
        msr_syscall_mask: msrs.syscall_mask,
        msr_efer: msrs.efer.into(),
        msr_tsc_aux: msrs.tsc_aux,
    }
}

/// Helper to convert a KVM ring-event segment to a `SegmentDescriptor`.
///
/// The kernel packs segment AR in VMX format (AVL=12, L=13, D/B=14, G=15),
/// but `SegmentAccess` uses compact format (AVL=8, L=9, D/B=10, G=11).
/// Convert by shifting bits 12-15 down to bits 8-11.
fn segment_from_kvm(seg: &kvm::sys::kvm_vmi_regs__bindgen_ty_1) -> SegmentDescriptor {
    let vmx_ar = seg.ar as u32;
    let compact_ar = (vmx_ar & 0xFF) | ((vmx_ar >> 4) & 0xF00);

    SegmentDescriptor {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector.into(),
        access: compact_ar.into(),
    }
}

/// Helper to convert a `SegmentDescriptor` to a KVM ring-event segment.
///
/// Converts from compact AR format (AVL=8, L=9, D/B=10, G=11) back to
/// VMX format (AVL=12, L=13, D/B=14, G=15).
fn segment_to_kvm(seg: &SegmentDescriptor) -> kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
    let compact_ar = u32::from(seg.access);
    let vmx_ar = (compact_ar & 0xFF) | ((compact_ar & 0xF00) << 4);

    kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector.into(),
        ar: vmx_ar as u16,
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
            ds: segment_from_kvm(&raw.ds),
            es: segment_from_kvm(&raw.es),
            fs: segment_from_kvm(&raw.fs),
            gs: segment_from_kvm(&raw.gs),
            ss: segment_from_kvm(&raw.ss),
            tr: SegmentDescriptor::default(),  // not in ring event
            ldtr: SegmentDescriptor::default(), // not in ring event

            idtr: Idtr::default(), // not in ring event
            gdtr: Gdtr::default(), // not in ring event

            sysenter_cs: raw.sysenter_cs,
            sysenter_esp: raw.sysenter_esp,
            sysenter_eip: raw.sysenter_eip,
            shadow_gs: raw.msr_kernel_gs_base,

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

            msr_efer: regs.msr_efer.into(),
            msr_star: regs.msr_star,
            msr_lstar: regs.msr_lstar,
            msr_cstar: regs.msr_cstar,
            msr_syscall_mask: regs.msr_syscall_mask,
            msr_kernel_gs_base: regs.shadow_gs,
            msr_tsc_aux: regs.msr_tsc_aux,
        }
    }
}
