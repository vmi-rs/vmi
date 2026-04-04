use vmi_arch_amd64::{
    Amd64, Cr0, Cr3, Cr4, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, MsrEfer, Registers, Rflags,
    SegmentDescriptor, Selector,
};
use vmi_core::VcpuId;

use crate::{ArchAdapter, Error, KdmpDriver};

impl ArchAdapter for Amd64 {
    fn registers(driver: &KdmpDriver<Self>, _vcpu: VcpuId) -> Result<Self::Registers, Error> {
        let headers = driver.dump.headers();
        let ctx = driver.dump.context_record();

        Ok(Registers {
            rax: ctx.rax,
            rbx: ctx.rbx,
            rcx: ctx.rcx,
            rdx: ctx.rdx,
            rsp: ctx.rsp,
            rbp: ctx.rbp,
            rsi: ctx.rsi,
            rdi: ctx.rdi,
            r8: ctx.r8,
            r9: ctx.r9,
            r10: ctx.r10,
            r11: ctx.r11,
            r12: ctx.r12,
            r13: ctx.r13,
            r14: ctx.r14,
            r15: ctx.r15,
            rip: ctx.rip,
            rflags: Rflags(ctx.eflags as u64),

            cr0: Cr0(0x80050031),
            cr3: Cr3(headers.directory_table_base),
            cr4: Cr4(0x350ef8),

            dr0: Dr0(ctx.dr0),
            dr1: Dr1(ctx.dr1),
            dr2: Dr2(ctx.dr2),
            dr3: Dr3(ctx.dr3),
            dr6: Dr6(ctx.dr6),
            dr7: Dr7(ctx.dr7),

            cs: SegmentDescriptor {
                selector: Selector(ctx.seg_cs),
                ..Default::default()
            },
            ds: SegmentDescriptor {
                selector: Selector(ctx.seg_ds),
                ..Default::default()
            },
            es: SegmentDescriptor {
                selector: Selector(ctx.seg_es),
                ..Default::default()
            },
            fs: SegmentDescriptor {
                selector: Selector(ctx.seg_fs),
                ..Default::default()
            },
            gs: SegmentDescriptor {
                selector: Selector(ctx.seg_gs),
                ..Default::default()
            },
            ss: SegmentDescriptor {
                selector: Selector(ctx.seg_ss),
                ..Default::default()
            },

            msr_lstar: headers.ps_active_process_head,
            msr_efer: MsrEfer(0x501),

            ..Default::default()
        })
    }
}
