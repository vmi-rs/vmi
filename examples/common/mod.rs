use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiCore, VmiSession, arch::amd64::Amd64, driver::xen::VmiXenDriver,
    os::windows::WindowsOs,
};

pub fn create_vmi_session() -> Result<VmiSession<'static, WindowsOs<VmiXenDriver<Amd64>>>, Error> {
    let filter = EnvFilter::default()
        .add_directive(tracing::Level::DEBUG.into())
        .add_directive("reqwest=warn".parse()?)
        .add_directive("rustls=warn".parse()?);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::try_from_env()?
        .context("invalid VMI_XEN_DOMAIN environment variable")?;
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
        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let entry = Box::leak(Box::new(entry));
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("creating VMI session");
    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;

    // Please don't do this in production code.
    // This is only done for the sake of the example.
    let core = Box::leak(Box::new(core));
    let os = Box::leak(Box::new(os));

    Ok(VmiSession::new(core, os))
}
