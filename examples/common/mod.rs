//! Logging, VMI and kernel profile bootstrap shared by the examples.

#![allow(
    dead_code,
    reason = "each example uses a different subset of these helpers"
)]

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context as _, Error};
use isr::{Profile, cache::IsrCache};
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::windows::{WindowsKernelInformation, WindowsOs},
};

/// A VMI setup that attaches the driver on creation and detaches it on drop.
pub struct VmiSetup {
    core: VmiCore<VmiXenDriver<Amd64>>,
    os: WindowsOs<VmiXenDriver<Amd64>>,
    isr: IsrCache,
    profile: Profile<'static>,
    kernel_info: WindowsKernelInformation,
    terminate_flag: Arc<AtomicBool>,
}

impl VmiSetup {
    /// Creates a new VMI setup and loads the kernel profile.
    pub fn new() -> Result<Self, Error> {
        let filter = EnvFilter::default()
            .add_directive(tracing::Level::DEBUG.into())
            .add_directive("reqwest=warn".parse()?)
            .add_directive("rustls=warn".parse()?);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();

        // Turn Ctrl-C into a clean shutdown.
        let terminate_flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

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
        let entry = isr.entry_from_codeview(kernel_info.codeview.clone())?;

        // Please don't do this in production code.
        // This is only done for the sake of the example.
        let entry = Box::leak(Box::new(entry));
        let profile = entry.profile()?;

        tracing::info!("creating VMI session");
        let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;

        Ok(Self {
            core,
            os,
            isr,
            profile,
            kernel_info,
            terminate_flag,
        })
    }

    /// Creates a VMI session.
    pub fn session(&self) -> VmiSession<'_, WindowsOs<VmiXenDriver<Amd64>>> {
        VmiSession::new(&self.core, &self.os)
    }

    /// Returns the kernel ISR profile of the VMI session.
    pub fn profile(&self) -> &Profile<'static> {
        &self.profile
    }

    /// Returns the ISR symbol cache.
    pub fn isr(&self) -> &IsrCache {
        &self.isr
    }

    /// Returns the kernel image information.
    pub fn kernel_info(&self) -> &WindowsKernelInformation {
        &self.kernel_info
    }

    /// Returns the flag set on `SIGHUP`, `SIGINT`, `SIGALRM` or `SIGTERM`.
    pub fn terminate_flag(&self) -> Arc<AtomicBool> {
        self.terminate_flag.clone()
    }
}
