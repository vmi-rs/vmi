use vmi_arch_amd64::Amd64;
use vmi_core::{VcpuId, VmiCore};
use vmi_driver_xen::VmiXenDriver;
use xen::XenStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain_id = 'x: {
        for name in &["win7", "win10", "win11", "ubuntu22"] {
            if let Some(domain_id) = XenStore::new()?.domain_id_from_name(name)? {
                break 'x domain_id;
            }
        }

        panic!("Domain not found");
    };

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
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
