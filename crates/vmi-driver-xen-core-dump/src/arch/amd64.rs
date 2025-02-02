use vmi_arch_amd64::{Amd64, Cr0, Cr2, Cr3, Cr4, Registers};
use vmi_core::VcpuId;

use crate::{ArchAdapter, Error, XenCoreDumpDriver};

impl ArchAdapter for Amd64 {
    fn registers(driver: &XenCoreDumpDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error> {
        let prstatus = driver.dump.xen_prstatus()?;

        Ok(Registers {
            cr0: Cr0(prstatus[vcpu.0 as usize].ctrlreg[0]),
            cr2: Cr2(prstatus[vcpu.0 as usize].ctrlreg[2]),
            cr3: Cr3(prstatus[vcpu.0 as usize].ctrlreg[3]),
            cr4: Cr4(prstatus[vcpu.0 as usize].ctrlreg[4]),
            ..Default::default()
        })
    }
}
