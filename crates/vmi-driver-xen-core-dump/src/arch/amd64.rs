use vmi_arch_amd64::{Amd64, Cr0, Cr2, Cr3, Cr4, MsrEfer, Registers};
use vmi_core::{VcpuId, VmiError};

use crate::{ArchAdapter, VmiXenCoreDumpDriver};

impl ArchAdapter for Amd64 {
    fn registers(
        driver: &VmiXenCoreDumpDriver<Self>,
        vcpu: VcpuId,
    ) -> Result<Self::Registers, VmiError> {
        let prstatus = driver.dump.xen_prstatus().map_err(VmiError::driver)?;

        Ok(Registers {
            cr0: Cr0(prstatus[vcpu.0 as usize].ctrlreg[0]),
            cr2: Cr2(prstatus[vcpu.0 as usize].ctrlreg[2]),
            cr3: Cr3(prstatus[vcpu.0 as usize].ctrlreg[3]),
            cr4: Cr4(prstatus[vcpu.0 as usize].ctrlreg[4]),
            msr_efer: MsrEfer(0x501),
            ..Default::default()
        })
    }
}
