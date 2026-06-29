//! This example demonstrates how to connect to a running Xen domain and
//! print the interrupt descriptor table (IDT) for each vCPU.

use anyhow::{Context as _, Error};
use vmi_arch_amd64::Amd64;
use vmi_core::{VcpuId, VmiCore};
use vmi_driver_xen::VmiXenDriver;

fn main() -> Result<(), Error> {
    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::try_from_env()?
        .context("invalid VMI_XEN_DOMAIN environment variable")?;
    let vmi = VmiCore::new(driver)?;

    // Get the interrupt descriptor table for each vCPU and print it.
    let _pause_guard = vmi.pause_guard()?;
    let info = vmi.info()?;
    for vcpu_id in 0..info.vcpus {
        let registers = vmi.registers(VcpuId(vcpu_id))?;
        let idt = Amd64::interrupt_descriptor_table(&vmi, &registers)?;

        println!("IDT[{vcpu_id}]: {idt:#?}");
    }

    Ok(())
}
