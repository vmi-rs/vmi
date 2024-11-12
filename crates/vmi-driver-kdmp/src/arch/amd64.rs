use vmi_arch_amd64::{Amd64, Cr0, Cr3, Cr4, MsrEfer, Registers};
use vmi_core::VcpuId;

use crate::{ArchAdapter, Error, KdmpDriver};

impl ArchAdapter for Amd64 {
    fn registers(driver: &KdmpDriver<Self>, _vcpu: VcpuId) -> Result<Self::Registers, Error> {
        let headers = driver.dump.headers();

        Ok(Registers {
            cr0: Cr0(0x80050031),
            cr3: Cr3(headers.directory_table_base),
            cr4: Cr4(0x350ef8),
            msr_lstar: headers.ps_active_process_head,
            msr_efer: MsrEfer(0x501),
            ..Default::default()
        })
    }
}
