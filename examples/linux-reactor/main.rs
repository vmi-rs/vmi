//! This example demonstrates how to use the `vmi_utils::reactor` module to
//! monitor certain events in a Linux guest VM.
//!
//! In particular, we monitor these functions:
//!
//! - `vfs_write` in the kernel logs the path of each file that a process
//!   writes.
//! - `tcp_v4_connect` in the kernel logs the destination of each IPv4 TCP
//!   connection.
//! - `fq_codel_dump` in the module `sch_fq_codel` logs the processes that
//!   read the settings of an `fq_codel` queueing discipline. The function is
//!   static, and the reactor finds it in the module's kallsyms.
//! - `getaddrinfo` in `libc.so.6` logs each host name that a process
//!   resolves.
//!
//! # Usage
//!
//! ```text
//! VMI_XEN_DOMAIN=<domain name or ID> cargo run --example linux-reactor \
//!     --features arch-amd64,driver-xen,os-linux,utils
//! ```
//!
//! isr finds the debug symbols of the kernel through its banner. Instead,
//! `--profile` names a profile that isr built before:
//!
//! ```text
//! VMI_XEN_DOMAIN=<domain name or ID> cargo run --example linux-reactor \
//!     --features arch-amd64,driver-xen,os-linux,utils -- --profile <path>
//! ```
//!
//! A breakpoint in a library follows the page tables of one process, and it
//! waits until that process maps the breakpoint's page. Without `--pid`, the
//! reactor takes the first process that maps `libc.so.6`, which may never
//! call `getaddrinfo`. `--pid` names a process that called it before, such
//! as one that looked up a host name. The processes share the library's
//! pages, and the breakpoint then fires in every process that calls the
//! function.
//!
//! `RUST_LOG=info` shows the events, and `RUST_LOG=debug` also shows how the
//! resolver finds each module and where the reactor puts each breakpoint.
//! A signal, such as the one that Ctrl+C sends, stops the example.
//!
//! # Log fields
//!
//! Each event logs one line at the `info` level in the spans `reactor`,
//! `interrupt` and the handler's own span, such as `vfs_write`. The span
//! `reactor` carries the fields `vcpu`, `view`, `pid` and `tid`, which name
//! the vCPU, the view, and the process and thread that hit the breakpoint.
//! The line of each event holds these fields:
//!
//! - `vfs_write` logs `path`, `pid` and `process`. `path` is the absolute
//!   path of the written file, and `pid` and `process` name the writing
//!   process.
//! - `tcp_v4_connect` logs `family`, `address` and `port`. `family` is 2
//!   (`AF_INET`) for IPv4, and `address` and `port` give the destination.
//! - `fq_codel_dump` logs `pid` and `process`. They name the process that
//!   asks for the settings, such as `tc`.
//! - `getaddrinfo` logs `host`, `pid` and `process`. `host` is the host
//!   name and is missing when the call asks for a local address. `pid` and
//!   `process` name the process that looks the name up.
//!
//! When the example stops, it logs the number of hits for each event as
//! `hit counts`.

mod kernel;
mod libc;
mod sch_fq_codel;

use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use clap::Parser;
use isr::cache::{Entry, IsrCache};
use signal_hook::consts::{SIGALRM, SIGHUP, SIGINT, SIGTERM};
use vmi::{
    VcpuId, VmiContext, VmiCore, VmiError, VmiHandlerExt as _, VmiOs, VmiRead, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{
        ProcessId,
        linux::{ArchAdapter, LinuxOs},
    },
    utils::{
        reactor::{Action, OsAdapter as _, Reactor, ReactorHandler, define_events, define_modules},
        resolver::resolve_user_module,
    },
};

/// Command-line interface for the `linux-reactor` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The guest kernel's profile, which replaces the one that isr finds
    /// through the kernel banner.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// PID of the process whose page tables the breakpoint in `libc.so.6`
    /// follows. Without it, the reactor takes the first process that maps
    /// the library.
    #[arg(long)]
    pid: Option<u32>,
}

/// Driver of the example.
type Driver = VmiXenDriver<Amd64>;

define_modules! {
    /// Modules used by the reactor.
    enum Module {
        /// The kernel module `sch_fq_codel`.
        #[module(name = "sch_fq_codel")]
        SchFqCodel,

        /// `libc.so.6`, in the process that `--pid` names or else in the
        /// first process that maps it.
        #[module(name = "libc.so.6", mode = user)]
        Libc,
    }

    #[resolver]
    struct ModuleResolver;

    #[cache]
    struct SymbolCache;
}

define_events! {
    /// Events monitored by the reactor.
    enum Event in Module {
        /// `vfs_write` in the kernel.
        #[event(name = "vfs_write")]
        VfsWrite,

        /// `tcp_v4_connect` in the kernel.
        #[event(name = "tcp_v4_connect")]
        TcpV4Connect,

        // `sch_fq_codel`
        SchFqCodel {
            /// `fq_codel_dump` in `sch_fq_codel`.
            #[event(name = "fq_codel_dump")]
            FqCodelDump,
        },

        // `libc.so.6`
        Libc {
            /// `getaddrinfo` in `libc.so.6`.
            #[event(name = "getaddrinfo")]
            GetAddrInfo,
        },
    }
}

/// The reactor's handler, which counts the hits of each event.
#[derive(Default)]
struct Monitor {
    /// The hits of `vfs_write`.
    vfs_write_counter: u64,

    /// The hits of `tcp_v4_connect`.
    tcp_v4_connect_counter: u64,

    /// The hits of `fq_codel_dump`.
    fq_codel_dump_counter: u64,

    /// The hits of `getaddrinfo`.
    getaddrinfo_counter: u64,
}

impl Monitor {
    /// Counts a hit of `vfs_write` and logs it.
    #[tracing::instrument(skip_all)]
    fn vfs_write<Driver>(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.vfs_write_counter += 1;
        kernel::vfs_write(vmi)
    }

    /// Counts a hit of `tcp_v4_connect` and logs it.
    #[tracing::instrument(skip_all)]
    fn tcp_v4_connect<Driver>(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.tcp_v4_connect_counter += 1;
        kernel::tcp_v4_connect(vmi)
    }

    /// Counts a hit of `fq_codel_dump` and logs it.
    #[tracing::instrument(skip_all)]
    fn fq_codel_dump<Driver>(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.fq_codel_dump_counter += 1;
        sch_fq_codel::fq_codel_dump(vmi)
    }

    /// Counts a hit of `getaddrinfo` and logs it.
    #[tracing::instrument(skip_all)]
    fn getaddrinfo<Driver>(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
    ) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture>, VmiError>
    where
        Driver: VmiRead,
        Driver::Architecture: ArchAdapter<Driver>,
    {
        self.getaddrinfo_counter += 1;
        libc::getaddrinfo(vmi)
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        tracing::info!(
            vfs_write = self.vfs_write_counter,
            tcp_v4_connect = self.tcp_v4_connect_counter,
            fq_codel_dump = self.fq_codel_dump_counter,
            getaddrinfo = self.getaddrinfo_counter,
            "hit counts"
        );
    }
}

impl<Driver> ReactorHandler<LinuxOs<Driver>> for Monitor
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Output = ();
    type Event = Event;

    fn handle_event(
        &mut self,
        vmi: &VmiContext<LinuxOs<Driver>>,
        event: Self::Event,
    ) -> Result<Action<<LinuxOs<Driver> as VmiOs>::Architecture, Self::Output>, VmiError> {
        match event {
            Self::Event::VfsWrite => self.vfs_write(vmi),
            Self::Event::TcpV4Connect => self.tcp_v4_connect(vmi),
            Self::Event::FqCodelDump => self.fq_codel_dump(vmi),
            Self::Event::GetAddrInfo => self.getaddrinfo(vmi),
        }
    }
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // A signal interrupts the wait for the next event, and the reactor then
    // removes its breakpoints. Without a handler, the signal would end the
    // process and leave the breakpoints in the guest.
    let terminate_flag = Arc::new(AtomicBool::new(false));
    for signal in [SIGHUP, SIGINT, SIGALRM, SIGTERM] {
        signal_hook::flag::register(signal, terminate_flag.clone())?;
    }

    let driver = Driver::try_from_env()?.context("set VMI_XEN_DOMAIN to a domain name or ID")?;
    let core = VmiCore::new(driver)?;

    // The banner names the kernel build, whose profile isr provides.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        LinuxOs::<Driver>::find_kernel(&core, &registers)?.context("no kernel banner found")?
    };

    let isr = IsrCache::new("cache")?;
    let entry = match cli.profile {
        Some(profile) => Entry::new(profile)?,
        None => isr.entry_from_linux_banner(&kernel_info.banner)?,
    };
    let profile = entry.profile()?;

    let os = LinuxOs::<Driver>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    let kernel_base = {
        let paused = session.pause_guard()?;
        paused.state().os().kernel_image_base()?
    };

    // The kernel's symbols come from its profile. `resolve` finds the module
    // and the library and loads their symbols. These are the kallsyms of
    // `sch_fq_codel` and the exports from `libc.so.6`.
    let mut cache = SymbolCache::default();
    let mut libc_entry = None;
    let mut resolver = ModuleResolver::default().with_kernel(kernel_base, &profile);

    // With `--pid`, the example resolves the library in that process by
    // hand, as `windows-reactor` does for `ncrypt.dll`. `resolve` then
    // leaves the library as it is.
    if let Some(pid) = cli.pid {
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        let resolved = resolve_user_module(&vmi, &isr, "libc.so.6", ProcessId(pid))?
            .context("libc.so.6 not found in the process")?;
        let symbols = LinuxOs::module_symbols(&vmi, &isr, &resolved, &mut libc_entry)?;

        resolver = resolver.with_module_in_process(
            Module::Libc,
            resolved.process,
            resolved.image_base,
            symbols,
        );
    }

    let modules = resolver.resolve(&session, &isr, &mut cache)?;

    let events = modules.into_events()?;

    session.handle(|session| {
        Ok(
            Reactor::new(session, Monitor::default(), events)?
                .with_termination_flag(terminate_flag),
        )
    })?;

    Ok(())
}
