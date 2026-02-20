use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
};
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
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        // Pause the VM to get consistent state.
        let _pause_guard = core.pause_guard()?;

        // Get the register state for the first vCPU.
        let registers = core.registers(VcpuId(0))?;

        // On AMD64 architecture, the kernel is usually found using the
        // `MSR_LSTAR` register, which contains the address of the system call
        // handler. This register is set by the operating system during boot
        // and is left unchanged (unless some rootkits are involved).
        //
        // Therefore, we can take an arbitrary registers at any point in time
        // (as long as the OS has booted and the page tables are set up) and
        // use them to find the kernel.
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
    let session = VmiSession::new(&core, &os);

    // Pause the VM again to get consistent state.
    let _pause_guard = session.pause_guard()?;

    // Create a new `VmiState` with the current register.
    let registers = session.registers(VcpuId(0))?;
    let vmi = session.with_registers(&registers);

    // Get the list of processes and print them.
    for process in vmi.os().processes()? {
        let process = process?;

        println!(
            "{} [{}] {} (root @ {})",
            process.object()?,
            process.id()?,
            process.name()?,
            process.translation_root()?
        );
    }

    Ok(())
}
