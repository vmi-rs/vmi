use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    arch::amd64::Amd64, driver::xen::VmiXenDriver, os::windows::WindowsOs, VcpuId, VmiCore,
    VmiSession,
};
use xen::XenStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain_id = 'x: {
        for name in &["win7", "win10", "win11", "ubuntu22"] {
            if let Some(domain_id) = XenStore::domain_id_from_name(name)? {
                break 'x domain_id;
            }
        }

        panic!("Domain not found");
    };

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(core, os);

    // Get the list of processes and print them.
    let _pause_guard = session.pause_guard()?;
    let registers = session.registers(VcpuId(0))?;
    let processes = session.os().processes(&registers)?;
    println!("Processes: {processes:#?}");

    Ok(())
}
