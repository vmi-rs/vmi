//! # [`recipe!`] example on Linux
//!
//! This example writes a file in a Linux guest from user mode. The recipe
//! takes over a thread in the process that `--pid` names, when the thread
//! returns from a syscall, and calls `open`, `write` and `close` in its C
//! library.
//!
//! # Usage
//!
//! ```bash
//! VMI_XEN_DOMAIN=linux-ubuntu26 cargo run --example linux-recipe-writefile \
//!     --features arch-amd64,driver-xen,os-linux,utils -- \
//!     --pid 1234 --path /tmp/vmi.txt --content "Hello, World!"
//! ```
//!
//! isr finds the debug symbols of the kernel through its banner. Instead,
//! `--profile` names a profile that isr built before.

use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use clap::Parser;
use isr::cache::{Entry, IsrCache};
use signal_hook::consts::{SIGALRM, SIGHUP, SIGINT, SIGTERM};
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::{VmiFullDriver, xen::VmiXenDriver},
    os::{ProcessId, linux::LinuxOs},
    trace::Hex,
    utils::injector::{Recipe, RecipeControlFlow, UserInjectorHandler, recipe},
};

/// Command-line interface for the `linux-recipe-writefile` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The guest kernel's profile, which replaces the one that isr finds
    /// through the kernel banner.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// PID of the process that writes the file.
    #[arg(long)]
    pid: u32,

    /// Path of the file in the guest.
    #[arg(long)]
    path: String,

    /// Content of the file.
    #[arg(long)]
    content: String,
}

/// Driver of the example.
type Driver = VmiXenDriver<Amd64>;

/// The file that the recipe writes.
#[derive(Debug)]
struct GuestFile {
    /// Path of the file in the guest.
    path: String,

    /// Content to write to the file.
    content: Vec<u8>,

    /// File descriptor that `open` returns.
    fd: u64,
}

/// Creates a recipe that writes a file in the guest.
///
/// # Equivalent C pseudo-code
///
/// ```c
/// int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
/// if (fd == -1) {
///     return;
/// }
///
/// write(fd, content, sizeof(content));
/// close(fd);
/// ```
fn recipe_factory<Driver>(data: GuestFile) -> Recipe<LinuxOs<Driver>, GuestFile>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    recipe![
        Recipe::<LinuxOs<Driver>>::new(data),
        //
        // Step 1:
        // - Open the file
        //
        {
            tracing::info!(path = data![path], "step 1: libc!open()");

            const O_WRONLY: u64 = 0o1;
            const O_CREAT: u64 = 0o100;
            const O_TRUNC: u64 = 0o1000;
            const MODE: u64 = 0o644;

            inject! {
                libc!open(
                    &data![path],               // pathname
                    O_WRONLY | O_CREAT | O_TRUNC, // flags
                    MODE                        // mode
                )
            }
        },
        //
        // Step 2:
        // - Verify the file descriptor
        // - Write the content to the file
        //
        {
            let return_value = registers!().rax as i32;

            if return_value == -1 {
                tracing::error!(
                    errno = ?vmi!().os().last_error()?,
                    "step 2: libc!open() failed"
                );

                return Ok(RecipeControlFlow::Break);
            }

            data![fd] = u64::from(return_value as u32);

            tracing::info!(fd = data![fd], "step 2: libc!write()");

            inject! {
                libc!write(
                    data![fd],                  // fd
                    data![content],             // buf
                    data![content].len()        // count
                )
            }
        },
        //
        // Step 3:
        // - Verify that the `write()` call succeeded
        // - Close the file
        //
        {
            let return_value = registers!().rax as i64;

            if return_value == -1 {
                tracing::error!(
                    errno = ?vmi!().os().last_error()?,
                    "step 3: libc!write() failed"
                );
            }
            else {
                tracing::info!(bytes_written = return_value, "step 3: libc!write()");
            }

            tracing::info!(fd = data![fd], "step 3: libc!close()");

            inject! {
                libc!close(
                    data![fd]                   // fd
                )
            }
        },
        //
        // Step 4:
        // - Verify that the `close()` call succeeded
        //
        {
            let return_value = registers!().rax;
            tracing::info!(return_value = %Hex(return_value), "step 4: libc!close()");

            Ok(RecipeControlFlow::Continue)
        },
    ]
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // A signal interrupts the wait for the next event, and the injector then
    // ends cleanly. Without a handler, the signal would end the process and
    // leave the guest's vCPUs waiting for replies.
    let interrupted = Arc::new(AtomicBool::new(false));
    for signal in [SIGHUP, SIGINT, SIGALRM, SIGTERM] {
        signal_hook::flag::register(signal, interrupted.clone())?;
    }

    let driver = Driver::try_from_env()?.context("set VMI_XEN_DOMAIN to a domain name or ID")?;
    let core = VmiCore::new(driver)?;

    // The banner names the kernel build, whose profile isr provides.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        LinuxOs::<Driver>::find_kernel(&core, &registers)?.context("no kernel banner found")?
    };

    let entry = match cli.profile {
        Some(profile) => Entry::new(profile)?,
        None => IsrCache::new("cache")?.entry_from_linux_banner(&kernel_info.banner)?,
    };
    let profile = entry.profile()?;

    let os = LinuxOs::<Driver>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    session
        .handle(|session| {
            UserInjectorHandler::new(
                session,
                recipe_factory(GuestFile {
                    path: cli.path.clone(),
                    content: cli.content.clone().into_bytes(),
                    fd: 0,
                }),
            )?
            .with_pid(ProcessId(cli.pid))
        })?
        .transpose()?;

    Ok(())
}
