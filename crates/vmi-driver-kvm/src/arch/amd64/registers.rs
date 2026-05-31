//! Conversions between KVM register structs and the amd64 `Registers` type.

use vmi_arch_amd64::{Gdtr, Granularity, Idtr, Registers, SegmentAccess, SegmentDescriptor};

use crate::convert::FromExt;

/// Packs the typed bitfields of a `KvmSegment` into the amd64 access-rights
/// layout: type bits 0-3, s bit 4, dpl bits 5-6, present bit 7, avl bit 8,
/// l bit 9, db bit 10, g bit 11.
///
/// `kvm_segment.unusable` is intentionally not modeled in the amd64 AR. KVM
/// reflects an unusable segment via `present = 0`, which IS carried here, so
/// the round-trip uses present as the proxy for usability.
fn kvm_segment_ar(s: &kvm::arch::x86::KvmSegment) -> u32 {
    (u32::from(s.type_) & 0b1111)
        | ((u32::from(s.s) & 1) << 4)
        | ((u32::from(s.dpl) & 0b11) << 5)
        | ((u32::from(s.present) & 1) << 7)
        | ((u32::from(s.avl) & 1) << 8)
        | ((u32::from(s.l) & 1) << 9)
        | ((u32::from(s.db) & 1) << 10)
        | ((u32::from(s.g) & 1) << 11)
}

/// Unpacks an amd64 access-rights value back into the typed bitfields of a
/// `KvmSegment`. The inverse of `kvm_segment_ar`.
fn unpack_ar_into(s: &mut kvm::arch::x86::KvmSegment, access: SegmentAccess) {
    let ar = access.0;
    s.type_ = (ar & 0b1111) as u8;
    s.s = ((ar >> 4) & 1) as u8;
    s.dpl = ((ar >> 5) & 0b11) as u8;
    s.present = ((ar >> 7) & 1) as u8;
    s.avl = ((ar >> 8) & 1) as u8;
    s.l = ((ar >> 9) & 1) as u8;
    s.db = ((ar >> 10) & 1) as u8;
    s.g = ((ar >> 11) & 1) as u8;
}

/// Translates the packed segment access-rights word carried in `kvm_vmi_regs`
/// segments into the amd64 `SegmentAccess` layout.
///
/// The ring event stores access rights in the VMX AR-bytes layout (SDM
/// 24.4.1): AVL bit 12, L bit 13, D/B bit 14, G bit 15. `SegmentAccess` uses
/// the compact layout shared with `kvm_segment_ar`: AVL bit 8, L bit 9, D/B
/// bit 10, G bit 11. The low byte (type, S, DPL, P) occupies the same
/// positions in both, so only the upper nibble is shifted down by four.
fn segment_access_from_vmx_ar(ar: u16) -> SegmentAccess {
    let ar = u32::from(ar);
    SegmentAccess((ar & 0x00ff) | ((ar >> 4) & 0x0f00))
}

/// Packs an amd64 `SegmentAccess` back into the VMX AR-bytes layout used by
/// `kvm_vmi_regs` segments. The inverse of `segment_access_from_vmx_ar`.
fn vmx_ar_from_segment_access(access: SegmentAccess) -> u16 {
    ((access.0 & 0x00ff) | ((access.0 & 0x0f00) << 4)) as u16
}

/// Converts one `KvmSegment` into an amd64 `SegmentDescriptor`.
fn seg(s: &kvm::arch::x86::KvmSegment) -> SegmentDescriptor {
    SegmentDescriptor {
        base: s.base,
        limit: s.limit,
        selector: s.selector.into(),
        access: SegmentAccess(kvm_segment_ar(s)),
    }
}

/// Converts an amd64 `SegmentDescriptor` into a `KvmSegment`.
fn unseg(d: &SegmentDescriptor) -> kvm::arch::x86::KvmSegment {
    let mut s = kvm::arch::x86::KvmSegment {
        base: d.base,
        limit: d.limit,
        selector: d.selector.into(),
        ..Default::default()
    };
    unpack_ar_into(&mut s, d.access);
    s
}

impl FromExt<kvm::arch::x86::Registers> for Registers {
    fn from_ext(value: kvm::arch::x86::Registers) -> Self {
        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rbp: value.rbp,
            rsi: value.rsi,
            rdi: value.rdi,
            rsp: value.rsp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags.into(),

            cr0: value.cr0.into(),
            cr2: value.cr2.into(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),

            dr0: value.db[0].into(),
            dr1: value.db[1].into(),
            dr2: value.db[2].into(),
            dr3: value.db[3].into(),
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),

            cs: seg(&value.cs),
            ds: seg(&value.ds),
            es: seg(&value.es),
            fs: seg(&value.fs),
            gs: seg(&value.gs),
            ss: seg(&value.ss),
            tr: seg(&value.tr),
            ldtr: seg(&value.ldt),

            idtr: Idtr {
                base: value.idt.base,
                limit: u32::from(value.idt.limit),
            },
            gdtr: Gdtr {
                base: value.gdt.base,
                limit: u32::from(value.gdt.limit),
            },

            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            shadow_gs: value.kernel_gs_base,

            msr_flags: value.sfmask,
            msr_lstar: value.lstar,
            msr_star: value.star,
            msr_cstar: value.cstar,
            msr_syscall_mask: value.sfmask,
            msr_efer: value.efer.into(),
            msr_tsc_aux: value.tsc_aux,
        }
    }
}

impl FromExt<&kvm::sys::kvm_vmi_regs> for Registers {
    fn from_ext(value: &kvm::sys::kvm_vmi_regs) -> Self {
        /// Reconstructs a `SegmentDescriptor` from the packed in-event segment.
        fn iseg(s: &kvm::sys::kvm_vmi_regs__bindgen_ty_1) -> SegmentDescriptor {
            let access = segment_access_from_vmx_ar(s.ar);
            let limit = match access.granularity() {
                Granularity::Byte => s.limit,
                Granularity::Page4K => (((u64::from(s.limit) + 1) << 12) - 1) as u32,
            };
            SegmentDescriptor {
                base: s.base,
                limit,
                selector: s.selector.into(),
                access,
            }
        }

        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rbp: value.rbp,
            rsi: value.rsi,
            rdi: value.rdi,
            rsp: value.rsp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags.into(),

            cr0: value.cr0.into(),
            cr2: Default::default(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),

            dr0: Default::default(),
            dr1: Default::default(),
            dr2: Default::default(),
            dr3: Default::default(),
            dr6: Default::default(),
            dr7: Default::default(),

            cs: iseg(&value.cs),
            ds: iseg(&value.ds),
            es: iseg(&value.es),
            fs: iseg(&value.fs),
            gs: iseg(&value.gs),
            ss: iseg(&value.ss),
            tr: SegmentDescriptor::default(),
            ldtr: SegmentDescriptor::default(),

            idtr: Idtr::default(),
            gdtr: Gdtr::default(),

            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            shadow_gs: value.msr_kernel_gs_base,

            msr_flags: value.msr_syscall_mask,
            msr_lstar: value.msr_lstar,
            msr_star: value.msr_star,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_efer: value.msr_efer.into(),
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

impl FromExt<&Registers> for kvm::sys::kvm_vmi_regs {
    fn from_ext(value: &Registers) -> Self {
        /// Packs a `SegmentDescriptor` into the in-event segment layout, where
        /// the limit is stored in the same granularity the `ar` byte encodes.
        fn iseg(d: &SegmentDescriptor) -> kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
            let limit = match d.access.granularity() {
                Granularity::Byte => d.limit,
                Granularity::Page4K => d.limit >> 12,
            };
            kvm::sys::kvm_vmi_regs__bindgen_ty_1 {
                base: d.base,
                limit,
                selector: d.selector.into(),
                ar: vmx_ar_from_segment_access(d.access),
            }
        }

        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rsi: value.rsi,
            rdi: value.rdi,
            rbp: value.rbp,
            rsp: value.rsp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags.into(),
            cr0: value.cr0.into(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),
            xcr0: 0,
            cs: iseg(&value.cs),
            ss: iseg(&value.ss),
            ds: iseg(&value.ds),
            es: iseg(&value.es),
            fs: iseg(&value.fs),
            gs: iseg(&value.gs),
            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            msr_efer: value.msr_efer.into(),
            msr_star: value.msr_star,
            msr_lstar: value.msr_lstar,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_kernel_gs_base: value.shadow_gs,
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

impl FromExt<&Registers> for kvm::arch::x86::Registers {
    fn from_ext(value: &Registers) -> Self {
        Self {
            rax: value.rax,
            rbx: value.rbx,
            rcx: value.rcx,
            rdx: value.rdx,
            rsi: value.rsi,
            rdi: value.rdi,
            rsp: value.rsp,
            rbp: value.rbp,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rip: value.rip,
            rflags: value.rflags.into(),

            cr0: value.cr0.into(),
            cr2: value.cr2.into(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),

            cs: unseg(&value.cs),
            ds: unseg(&value.ds),
            es: unseg(&value.es),
            fs: unseg(&value.fs),
            gs: unseg(&value.gs),
            ss: unseg(&value.ss),
            tr: unseg(&value.tr),
            ldt: unseg(&value.ldtr),

            gdt: kvm::arch::x86::KvmDtable {
                base: value.gdtr.base,
                limit: value.gdtr.limit as u16,
            },
            idt: kvm::arch::x86::KvmDtable {
                base: value.idtr.base,
                limit: value.idtr.limit as u16,
            },

            db: [
                value.dr0.into(),
                value.dr1.into(),
                value.dr2.into(),
                value.dr3.into(),
            ],
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),

            efer: value.msr_efer.into(),
            star: value.msr_star,
            lstar: value.msr_lstar,
            cstar: value.msr_cstar,
            sfmask: value.msr_syscall_mask,
            kernel_gs_base: value.shadow_gs,
            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            tsc_aux: value.msr_tsc_aux,
        }
    }
}

#[cfg(test)]
mod tests {
    use vmi_arch_amd64::{Granularity, SegmentAccess};

    use super::{segment_access_from_vmx_ar, vmx_ar_from_segment_access};

    #[test]
    fn vmx_ar_decodes_64bit_code_segment() {
        // A 64-bit kernel code segment in the VMX AR-bytes layout the kernel
        // writes into kvm_vmi_regs: type=0xb, S(4), P(7), L(13), G(15).
        let vmx_ar: u16 = 0xb | (1 << 4) | (1 << 7) | (1 << 13) | (1 << 15);

        let access = segment_access_from_vmx_ar(vmx_ar);
        assert!(access.long_mode());
        assert!(access.present());
        assert_eq!(access.typ(), 0xb);
        assert!(matches!(access.granularity(), Granularity::Page4K));

        // Wrapping the raw VMX word (the previous bug) lands L at bit 13, which
        // long_mode() reads at bit 9, so it would wrongly report 32-bit code.
        assert!(!SegmentAccess(u32::from(vmx_ar)).long_mode());

        // Round-trips back to the VMX layout the kernel expects.
        assert_eq!(vmx_ar_from_segment_access(access), vmx_ar);
    }
}
