use isr::{
    cache::{IsrCache, JsonCodec},
    Profile,
};
use vmi::{
    arch::amd64::Amd64, driver::xen::VmiXenDriver, os::windows::WindowsOs, VcpuId, VmiCore,
    VmiSession,
};
use xen::XenStore;

pub fn create_vmi_session() -> Result<
    (
        VmiSession<'static, VmiXenDriver<Amd64>, WindowsOs<VmiXenDriver<Amd64>>>,
        Profile<'static>,
    ),
    Box<dyn std::error::Error>,
> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let domain_id = 'x: {
        for name in &["win7", "win10", "win11", "ubuntu22"] {
            if let Some(domain_id) = XenStore::domain_id_from_name(name)? {
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
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.expect("kernel information")
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
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
