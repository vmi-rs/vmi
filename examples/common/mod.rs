#![allow(
    dead_code,
    reason = "each example uses a different subset of these helpers"
)]

use anyhow::{Context as _, Error};
use isr::{Profile, cache::IsrCache};
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{ProcessId, VmiOsProcess as _, windows::WindowsOs},
    utils::shellcode::{ParameterWriter, ShellcodeParameters},
};

/// Windows session over the Xen domain named by `VMI_XEN_DOMAIN`.
pub type WindowsSession = VmiSession<'static, WindowsOs<VmiXenDriver<Amd64>>>;

/// Creates a VMI session, discarding the kernel profile.
pub fn create_vmi_session() -> Result<WindowsSession, Error> {
    let (session, _profile) = create_vmi_session_with_profile()?;
    Ok(session)
}

/// Creates a VMI session and returns the kernel profile it was built from.
///
/// The profile is needed by consumers that place kernel breakpoints, such as
/// the page-table monitor and the deploy monitor.
pub fn create_vmi_session_with_profile() -> Result<(WindowsSession, Profile<'static>), Error> {
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

    Ok((VmiSession::new(core, os), profile))
}

/// Finds the configured target process while the guest is paused.
pub fn find_process_id(
    session: &VmiSession<'_, WindowsOs<VmiXenDriver<Amd64>>>,
    process_name: &str,
) -> Result<ProcessId, Error> {
    let paused = session.pause_guard()?;
    let vmi = paused.state();
    let process = vmi
        .os()
        .find_process(process_name)?
        .with_context(|| format!("process `{process_name}` not found"))?;

    let process_id = process.id()?;

    tracing::info!(
        process = process_name,
        pid = %process_id,
        "found target process"
    );

    Ok(process_id)
}

/// Encodes a shellcode parameter block for test assertions.
pub fn encode_parameters(parameters: &impl ShellcodeParameters) -> Vec<u8> {
    let mut output = Vec::new();
    parameters.encode(&mut ParameterWriter::new(&mut output));
    output
}
