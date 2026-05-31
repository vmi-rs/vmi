//! Conversions between KVM register structs and the amd64 `Registers` type.

use vmi_arch_amd64::{Gdtr, Granularity, Idtr, Registers, SegmentAccess, SegmentDescriptor};

use crate::convert::FromExt;

/// A full register snapshot read out-of-event via standard KVM ioctls.
pub struct KvmFullRegs {
    /// General-purpose registers from `KVM_GET_REGS`.
    pub regs: kvm::sys::kvm_regs,

    /// Special registers from `KVM_GET_SREGS`.
    pub sregs: kvm::sys::kvm_sregs,

    /// Debug registers from `KVM_GET_DEBUGREGS`.
    pub debugregs: kvm::sys::kvm_debugregs,

    /// MSR values read via `KVM_GET_MSRS`.
    pub msrs: KvmMsrs,
}

/// The subset of MSRs the driver reads, named for clarity.
#[derive(Default)]
pub struct KvmMsrs {
    /// `IA32_EFER`.
    pub efer: u64,

    /// `IA32_STAR`.
    pub star: u64,

    /// `IA32_LSTAR`.
    pub lstar: u64,

    /// `IA32_CSTAR`.
    pub cstar: u64,

    /// `IA32_FMASK` (syscall flag mask).
    pub sfmask: u64,

    /// `IA32_KERNEL_GS_BASE` (the swapped-out GS base).
    pub kernel_gs_base: u64,

    /// `IA32_SYSENTER_CS`.
    pub sysenter_cs: u64,

    /// `IA32_SYSENTER_ESP`.
    pub sysenter_esp: u64,

    /// `IA32_SYSENTER_EIP`.
    pub sysenter_eip: u64,

    /// `IA32_TSC_AUX`.
    pub tsc_aux: u64,
}

/// Packs the typed bitfields of a `kvm_segment` into the amd64 access-rights
/// layout: type bits 0-3, s bit 4, dpl bits 5-6, present bit 7, avl bit 8,
/// l bit 9, db bit 10, g bit 11.
///
/// `kvm_segment.unusable` is intentionally not modeled in the amd64 AR. KVM
/// reflects an unusable segment via `present = 0`, which IS carried here, so
/// the round-trip uses present as the proxy for usability.
fn kvm_segment_ar(s: &kvm::sys::kvm_segment) -> u32 {
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
/// `kvm_segment`. The inverse of `kvm_segment_ar`.
fn unpack_ar_into(s: &mut kvm::sys::kvm_segment, access: SegmentAccess) {
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

/// Converts one `kvm_segment` into an amd64 `SegmentDescriptor`.
fn seg(s: &kvm::sys::kvm_segment) -> SegmentDescriptor {
    SegmentDescriptor {
        base: s.base,
        limit: s.limit,
        selector: s.selector.into(),
        access: SegmentAccess(kvm_segment_ar(s)),
    }
}

/// Converts an amd64 `SegmentDescriptor` into a `kvm_segment`.
fn unseg(d: &SegmentDescriptor) -> kvm::sys::kvm_segment {
    let mut s = kvm::sys::kvm_segment {
        base: d.base,
        limit: d.limit,
        selector: d.selector.into(),
        ..Default::default()
    };
    unpack_ar_into(&mut s, d.access);
    s
}

impl FromExt<KvmFullRegs> for Registers {
    fn from_ext(value: KvmFullRegs) -> Self {
        let regs = &value.regs;
        let sregs = &value.sregs;
        let debugregs = &value.debugregs;
        let msrs = &value.msrs;

        Self {
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

            dr0: debugregs.db[0].into(),
            dr1: debugregs.db[1].into(),
            dr2: debugregs.db[2].into(),
            dr3: debugregs.db[3].into(),
            dr6: debugregs.dr6.into(),
            dr7: debugregs.dr7.into(),

            cs: seg(&sregs.cs),
            ds: seg(&sregs.ds),
            es: seg(&sregs.es),
            fs: seg(&sregs.fs),
            gs: seg(&sregs.gs),
            ss: seg(&sregs.ss),
            tr: seg(&sregs.tr),
            ldtr: seg(&sregs.ldt),

            idtr: Idtr {
                base: sregs.idt.base,
                limit: u32::from(sregs.idt.limit),
            },
            gdtr: Gdtr {
                base: sregs.gdt.base,
                limit: u32::from(sregs.gdt.limit),
            },

            sysenter_cs: msrs.sysenter_cs,
            sysenter_esp: msrs.sysenter_esp,
            sysenter_eip: msrs.sysenter_eip,
            shadow_gs: msrs.kernel_gs_base,

            msr_flags: msrs.sfmask,
            msr_lstar: msrs.lstar,
            msr_star: msrs.star,
            msr_cstar: msrs.cstar,
            msr_syscall_mask: msrs.sfmask,
            msr_efer: msrs.efer.into(),
            msr_tsc_aux: msrs.tsc_aux,
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

impl FromExt<&Registers> for kvm::sys::kvm_regs {
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

impl FromExt<&Registers> for kvm::sys::kvm_sregs {
    fn from_ext(value: &Registers) -> Self {
        Self {
            cs: unseg(&value.cs),
            ds: unseg(&value.ds),
            es: unseg(&value.es),
            fs: unseg(&value.fs),
            gs: unseg(&value.gs),
            ss: unseg(&value.ss),
            tr: unseg(&value.tr),
            ldt: unseg(&value.ldtr),
            gdt: kvm::sys::kvm_dtable {
                base: value.gdtr.base,
                limit: value.gdtr.limit as u16,
                ..Default::default()
            },
            idt: kvm::sys::kvm_dtable {
                base: value.idtr.base,
                limit: value.idtr.limit as u16,
                ..Default::default()
            },
            cr0: value.cr0.into(),
            cr2: value.cr2.into(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),
            efer: value.msr_efer.into(),
            ..Default::default()
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
