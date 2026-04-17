use vmi_arch_amd64::{
    Amd64, Cr0, Cr3, Cr4, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, MsrEfer, Registers, Rflags,
    SegmentDescriptor, Selector,
};
use vmi_core::VcpuId;

use super::{
    ArchAdapter,
    header64::{ExceptionRecord64, Header64},
};
use crate::{KdmpDriver, KdmpDriverError};

impl ArchAdapter for Amd64 {
    type Header = Header64;
    type ExceptionRecord = ExceptionRecord64;

    fn header(driver: &KdmpDriver<Self>) -> Self::Header {
        let header = driver.dump.headers();

        Header64 {
            signature: header.signature,
            valid_dump: header.valid_dump,
            major_version: header.major_version,
            minor_version: header.minor_version,
            directory_table_base: header.directory_table_base,
            pfn_database: header.pfn_database,
            ps_loaded_module_list: header.ps_loaded_module_list,
            ps_active_process_head: header.ps_active_process_head,
            machine_image_type: header.machine_image_type,
            number_processors: header.number_processors,
            bug_check_code: header.bug_check_code,
            bug_check_parameter1: header.bug_check_code_parameters[0],
            bug_check_parameter2: header.bug_check_code_parameters[1],
            bug_check_parameter3: header.bug_check_code_parameters[2],
            bug_check_parameter4: header.bug_check_code_parameters[3],
            version_user: header.version_user,
            kd_debugger_data_block: header.kd_debugger_data_block,
            physical_memory_block_buffer: header.physical_memory_block_buffer,
            context_record_buffer: header.context_record_buffer,
            exception: ExceptionRecord64 {
                exception_code: header.exception.exception_code,
                exception_flags: header.exception.exception_flags,
                exception_record: header.exception.exception_record,
                exception_address: header.exception.exception_address,
                number_parameters: header.exception.number_parameters,
                exception_information: header.exception.exception_information,
            },
            dump_type: header.dump_type,
            required_dump_space: header.required_dump_space,
            system_time: header.system_time,
            comment: header.comment,
            system_up_time: header.system_up_time,
            minidump_fields: header.minidump_fields,
            secondary_data_state: header.secondary_data_state,
            product_type: header.product_type,
            suite_mask: header.suite_mask,
            writer_status: header.writer_status,
            kd_secondary_version: header.kd_secondary_version,
            attributes: header.attributes,
            boot_id: header.boot_id,
        }
    }

    fn registers(
        driver: &KdmpDriver<Self>,
        _vcpu: VcpuId,
    ) -> Result<Self::Registers, KdmpDriverError> {
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
