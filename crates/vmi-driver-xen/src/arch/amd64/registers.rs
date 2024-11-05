use vmi_arch_amd64::{Gdtr, Granularity, Idtr, Registers, SegmentAccess, SegmentDescriptor};
use xen::{
    arch::x86::Registers as XenRegisters,
    ctrl::{VmEventRegsX86, VmEventSelectorReg},
};

use crate::FromExt;

impl FromExt<XenRegisters> for Registers {
    fn from_ext(value: XenRegisters) -> Self {
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

            dr0: value.dr0.into(),
            dr1: value.dr1.into(),
            dr2: value.dr2.into(),
            dr3: value.dr3.into(),
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),

            cs: SegmentDescriptor {
                base: value.cs_base,
                limit: value.cs_limit,
                selector: value.cs_sel.into(),
                access: value.cs_arbytes.into(),
            },
            ds: SegmentDescriptor {
                base: value.ds_base,
                limit: value.ds_limit,
                selector: value.ds_sel.into(),
                access: value.ds_arbytes.into(),
            },
            es: SegmentDescriptor {
                base: value.es_base,
                limit: value.es_limit,
                selector: value.es_sel.into(),
                access: value.es_arbytes.into(),
            },
            fs: SegmentDescriptor {
                base: value.fs_base,
                limit: value.fs_limit,
                selector: value.fs_sel.into(),
                access: value.fs_arbytes.into(),
            },
            gs: SegmentDescriptor {
                base: value.gs_base,
                limit: value.gs_limit,
                selector: value.gs_sel.into(),
                access: value.gs_arbytes.into(),
            },
            ss: SegmentDescriptor {
                base: value.ss_base,
                limit: value.ss_limit,
                selector: value.ss_sel.into(),
                access: value.ss_arbytes.into(),
            },
            tr: SegmentDescriptor {
                base: value.tr_base,
                limit: value.tr_limit,
                selector: value.tr_sel.into(),
                access: value.tr_arbytes.into(),
            },
            ldtr: SegmentDescriptor {
                base: value.ldtr_base,
                limit: value.ldtr_limit,
                selector: value.ldtr_sel.into(),
                access: value.ldtr_arbytes.into(),
            },

            idtr: Idtr {
                base: value.idtr_base,
                limit: value.idtr_limit,
            },
            gdtr: Gdtr {
                base: value.gdtr_base,
                limit: value.gdtr_limit,
            },

            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            shadow_gs: value.shadow_gs,

            msr_flags: value.msr_flags,
            msr_lstar: value.msr_lstar,
            msr_star: value.msr_star,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_efer: value.msr_efer.into(),
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

impl FromExt<Registers> for XenRegisters {
    fn from_ext(value: Registers) -> Self {
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

            dr0: value.dr0.into(),
            dr1: value.dr1.into(),
            dr2: value.dr2.into(),
            dr3: value.dr3.into(),
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),

            cs_base: value.cs.base,
            cs_limit: value.cs.limit,
            cs_sel: value.cs.selector.into(),
            cs_arbytes: value.cs.access.into(),

            ds_base: value.ds.base,
            ds_limit: value.ds.limit,
            ds_sel: value.ds.selector.into(),
            ds_arbytes: value.ds.access.into(),

            es_base: value.es.base,
            es_limit: value.es.limit,
            es_sel: value.es.selector.into(),
            es_arbytes: value.es.access.into(),

            fs_base: value.fs.base,
            fs_limit: value.fs.limit,
            fs_sel: value.fs.selector.into(),
            fs_arbytes: value.fs.access.into(),

            gs_base: value.gs.base,
            gs_limit: value.gs.limit,
            gs_sel: value.gs.selector.into(),
            gs_arbytes: value.gs.access.into(),

            ss_base: value.ss.base,
            ss_limit: value.ss.limit,
            ss_sel: value.ss.selector.into(),
            ss_arbytes: value.ss.access.into(),

            tr_base: value.tr.base,
            tr_limit: value.tr.limit,
            tr_sel: value.tr.selector.into(),
            tr_arbytes: value.tr.access.into(),

            ldtr_base: value.ldtr.base,
            ldtr_limit: value.ldtr.limit,
            ldtr_sel: value.ldtr.selector.into(),
            ldtr_arbytes: value.ldtr.access.into(),

            idtr_base: value.idtr.base,
            idtr_limit: value.idtr.limit,

            gdtr_base: value.gdtr.base,
            gdtr_limit: value.gdtr.limit,

            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            shadow_gs: value.shadow_gs,

            msr_flags: value.msr_flags,
            msr_lstar: value.msr_lstar,
            msr_star: value.msr_star,
            msr_cstar: value.msr_cstar,
            msr_syscall_mask: value.msr_syscall_mask,
            msr_efer: value.msr_efer.into(),
            msr_tsc_aux: value.msr_tsc_aux,
        }
    }
}

impl FromExt<VmEventRegsX86> for Registers {
    fn from_ext(value: VmEventRegsX86) -> Self {
        Self::from_ext(&value)
    }
}

impl FromExt<&VmEventRegsX86> for Registers {
    fn from_ext(value: &VmEventRegsX86) -> Self {
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

            dr0: Default::default(),
            dr1: Default::default(),
            dr2: Default::default(),
            dr3: Default::default(),
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),

            cs: SegmentDescriptor {
                base: value.cs_base as _,
                limit: match SegmentAccess::from(value.cs.ar).granularity() {
                    Granularity::Byte => value.cs.limit,
                    Granularity::Page4K => (((u64::from(value.cs.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.cs_sel.into(),
                access: value.cs.ar.into(),
            },
            ds: SegmentDescriptor {
                base: value.ds_base as _,
                limit: match SegmentAccess::from(value.ds.ar).granularity() {
                    Granularity::Byte => value.ds.limit,
                    Granularity::Page4K => (((u64::from(value.ds.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.ds_sel.into(),
                access: value.ds.ar.into(),
            },
            es: SegmentDescriptor {
                base: value.es_base as _,
                limit: match SegmentAccess::from(value.es.ar).granularity() {
                    Granularity::Byte => value.es.limit,
                    Granularity::Page4K => (((u64::from(value.es.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.es_sel.into(),
                access: value.es.ar.into(),
            },
            fs: SegmentDescriptor {
                base: value.fs_base,
                limit: match SegmentAccess::from(value.fs.ar).granularity() {
                    Granularity::Byte => value.fs.limit,
                    Granularity::Page4K => (((u64::from(value.fs.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.fs_sel.into(),
                access: value.fs.ar.into(),
            },
            gs: SegmentDescriptor {
                base: value.gs_base,
                limit: match SegmentAccess::from(value.gs.ar).granularity() {
                    Granularity::Byte => value.gs.limit,
                    Granularity::Page4K => (((u64::from(value.gs.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.gs_sel.into(),
                access: value.gs.ar.into(),
            },
            ss: SegmentDescriptor {
                base: value.ss_base as _,
                limit: match SegmentAccess::from(value.ss.ar).granularity() {
                    Granularity::Byte => value.ss.limit,
                    Granularity::Page4K => (((u64::from(value.ss.limit) + 1) << 12) - 1) as u32,
                },
                selector: value.ss_sel.into(),
                access: value.ss.ar.into(),
            },
            tr: SegmentDescriptor::default(),
            ldtr: SegmentDescriptor::default(),

            idtr: Idtr::default(),
            gdtr: Gdtr {
                base: value.gdtr_base,
                limit: value.gdtr_limit as _,
            },

            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            shadow_gs: value.shadow_gs,

            msr_flags: Default::default(),
            msr_lstar: value.msr_lstar,
            msr_star: value.msr_star,
            msr_cstar: Default::default(),
            msr_syscall_mask: Default::default(),
            msr_efer: value.msr_efer.into(),
            msr_tsc_aux: Default::default(),
        }
    }
}

impl FromExt<Registers> for VmEventRegsX86 {
    fn from_ext(value: Registers) -> Self {
        Self {
            rax: value.rax,
            rcx: value.rcx,
            rdx: value.rdx,
            rbx: value.rbx,
            rsp: value.rsp,
            rbp: value.rbp,
            rsi: value.rsi,
            rdi: value.rdi,
            r8: value.r8,
            r9: value.r9,
            r10: value.r10,
            r11: value.r11,
            r12: value.r12,
            r13: value.r13,
            r14: value.r14,
            r15: value.r15,
            rflags: value.rflags.into(),
            dr6: value.dr6.into(),
            dr7: value.dr7.into(),
            rip: value.rip,
            cr0: value.cr0.into(),
            cr2: value.cr2.into(),
            cr3: value.cr3.into(),
            cr4: value.cr4.into(),
            sysenter_cs: value.sysenter_cs,
            sysenter_esp: value.sysenter_esp,
            sysenter_eip: value.sysenter_eip,
            msr_efer: value.msr_efer.into(),
            msr_star: value.msr_star,
            msr_lstar: value.msr_lstar,
            gdtr_base: value.gdtr.base,
            // npt_base: value.npt_base,
            // vmtrace_pos: value.vmtrace_pos,
            npt_base: 0,
            vmtrace_pos: 0,

            cs_base: value.cs.base as _,
            ss_base: value.ss.base as _,
            ds_base: value.ds.base as _,
            es_base: value.es.base as _,
            fs_base: value.fs.base,
            gs_base: value.gs.base,
            cs: VmEventSelectorReg {
                limit: match value.cs.access.granularity() {
                    Granularity::Byte => value.cs.limit,
                    Granularity::Page4K => value.cs.limit << 12,
                },
                ar: value.cs.access.into(),
            },
            ss: VmEventSelectorReg {
                limit: match value.ss.access.granularity() {
                    Granularity::Byte => value.ss.limit,
                    Granularity::Page4K => value.ss.limit << 12,
                },
                ar: value.ss.access.into(),
            },
            ds: VmEventSelectorReg {
                limit: match value.ds.access.granularity() {
                    Granularity::Byte => value.ds.limit,
                    Granularity::Page4K => value.ds.limit << 12,
                },
                ar: value.ds.access.into(),
            },
            es: VmEventSelectorReg {
                limit: match value.es.access.granularity() {
                    Granularity::Byte => value.es.limit,
                    Granularity::Page4K => value.es.limit << 12,
                },
                ar: value.es.access.into(),
            },
            fs: VmEventSelectorReg {
                limit: match value.fs.access.granularity() {
                    Granularity::Byte => value.fs.limit,
                    Granularity::Page4K => value.fs.limit << 12,
                },
                ar: value.fs.access.into(),
            },
            gs: VmEventSelectorReg {
                limit: match value.gs.access.granularity() {
                    Granularity::Byte => value.gs.limit,
                    Granularity::Page4K => value.gs.limit << 12,
                },
                ar: value.gs.access.into(),
            },
            shadow_gs: value.shadow_gs,
            gdtr_limit: value.gdtr.limit as _,
            cs_sel: value.cs.selector.into(),
            ss_sel: value.ss.selector.into(),
            ds_sel: value.ds.selector.into(),
            es_sel: value.es.selector.into(),
            fs_sel: value.fs.selector.into(),
            gs_sel: value.gs.selector.into(),
        }
    }
}
