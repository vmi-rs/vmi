use isr::{Profile, cache::IsrCache};
use vmi::{
    VcpuId, VmiCore, VmiError, VmiOs, VmiSession, VmiState,
    arch::amd64::Amd64,
    driver::{VmiRead, xen::VmiXenDriver},
    os::{VmiOsProcess as _, windows::WindowsOs},
};
use xen::XenStore;

pub type Session = (
    VmiSession<'static, WindowsOs<VmiXenDriver<Amd64>>>,
    Profile<'static>,
);

pub fn create_vmi_session() -> Result<Session, Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let domain_id = 'x: {
        for name in &["win7", "win10", "win11", "ubuntu22"] {
            if let Some(domain_id) = XenStore::new()?.domain_id_from_name(name)? {
                break 'x domain_id;
            }
        }

        panic!("Domain not found");
    };

    tracing::debug!(?domain_id);

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::new(domain_id)?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        // Pause the vCPU to get consistent state.
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
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let entry = Box::leak(Box::new(entry));
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;

    // Please don't do this in production code.
    // This is only done for the sake of the example.
    let core = Box::leak(Box::new(core));
    let os = Box::leak(Box::new(os));

    Ok((VmiSession::new(core, os), profile))
}

pub fn find_process<'a, Os>(
    vmi: &VmiState<'a, Os>,
    name: &str,
) -> Result<Option<Os::Process<'a>>, VmiError>
where
    Os: VmiOs,
    Os::Driver: VmiRead,
{
    for process in vmi.os().processes()? {
        let process = process?;

        if process.name()?.to_lowercase() == name {
            return Ok(Some(process));
        }
    }

    Ok(None)
}
