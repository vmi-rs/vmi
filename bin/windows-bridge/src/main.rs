mod msgbox;
mod pull;

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context as _, Error};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiContext, VmiCore, VmiError, VmiOs, VmiRead, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{
        VmiOsProcess as _,
        windows::{ArchAdapter, WindowsOs, WindowsProcess},
    },
    utils::reactor::{Action, Reactor, ReactorHandler, define_events, define_modules},
};

fn main() -> Result<(), Error> {
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
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    Ok(())
}
