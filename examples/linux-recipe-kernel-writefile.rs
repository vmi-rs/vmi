//! # [`recipe!`] example in the Linux kernel
//!
//! This example writes a file in a Linux guest from kernel mode. The recipe
//! takes over a thread at `x64_sys_call`, in the process that `--pid` names
//! or in the first one that makes a syscall, and calls the kernel's
//! `filp_open`, `kernel_write` and `filp_close`. The file belongs to the
//! user of that process.
//!
//! # Usage
//!
//! ```bash
//! VMI_XEN_DOMAIN=linux-ubuntu26 cargo run --example linux-recipe-kernel-writefile \
//!     --features arch-amd64,driver-xen,os-linux,utils -- \
//!     --path /tmp/vmi.txt --content "Hello, World!"
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
    Va, VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::{VmiFullDriver, xen::VmiXenDriver},
    os::{ProcessId, linux::LinuxOs},
    trace::Hex,
    utils::injector::{KernelInjectorHandler, Recipe, RecipeControlFlow, recipe},
};

/// Command-line interface for the `linux-recipe-kernel-writefile` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The guest kernel's profile, which replaces the one that isr finds
    /// through the kernel banner.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// PID of the process whose thread writes the file. Without it, the
    /// first process that makes a syscall writes it.
    #[arg(long)]
    pid: Option<u32>,

    /// Path of the file in the guest.
    #[arg(long)]
    path: String,

    /// Content of the file.
    #[arg(long)]
    content: String,
}

/// Driver of the example.
type Driver = VmiXenDriver<Amd64>;

/// The largest error number that the kernel returns in a pointer
/// (`MAX_ERRNO`).
const MAX_ERRNO: u64 = 4095;

/// The file that the recipe writes.
#[derive(Debug)]
struct GuestFile {
    /// Path of the file in the guest.
    path: String,

    /// Content to write to the file.
    content: Vec<u8>,

    /// The `struct file` that `filp_open` returns.
    file: u64,

    /// The file position that `kernel_write` moves.
    position_ptr: Va,
}

/// Checks if a pointer that the kernel returns holds an error number
/// (`IS_ERR`).
fn is_error_pointer(value: u64) -> bool {
    value >= MAX_ERRNO.wrapping_neg()
}

/// Creates a recipe that writes a file in the guest.
///
/// # Equivalent C pseudo-code
///
/// ```c
/// struct file *file = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
/// if (IS_ERR(file)) {
///     return;
/// }
///
/// loff_t position = 0;
/// kernel_write(file, content, sizeof(content), &position);
/// filp_close(file, NULL);
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
            tracing::info!(path = data![path], "step 1: kernel!filp_open()");

            const O_WRONLY: u64 = 0o1;
            const O_CREAT: u64 = 0o100;
            const O_TRUNC: u64 = 0o1000;
            const MODE: u64 = 0o644;

            inject! {
                kernel!filp_open(
                    &data![path],               // filename
                    O_WRONLY | O_CREAT | O_TRUNC, // flags
                    MODE                        // mode
                )
            }
        },
        //
        // Step 2:
        // - Verify the file
        // - Write the content to the file
        //
        {
            let return_value = registers!().rax;

            if is_error_pointer(return_value) {
                tracing::error!(
                    errno = return_value.wrapping_neg(),
                    "step 2: kernel!filp_open() failed"
                );

                return Ok(RecipeControlFlow::Break);
            }

            data![file] = return_value;
            data![position_ptr] = copy_to_stack!(0u64)?;

            tracing::info!(file = %Hex(data![file]), "step 2: kernel!kernel_write()");

            inject! {
                kernel!kernel_write(
                    data![file],                // file
                    data![content],             // buf
                    data![content].len(),       // count
                    data![position_ptr]         // pos
                )
            }
        },
        //
        // Step 3:
        // - Verify that the `kernel_write()` call succeeded
        // - Close the file
        //
        {
            let return_value = registers!().rax as i64;

            if return_value < 0 {
                tracing::error!(
                    errno = -return_value,
                    "step 3: kernel!kernel_write() failed"
                );
            }
            else {
                tracing::info!(
                    bytes_written = return_value,
                    "step 3: kernel!kernel_write()"
                );
            }

            tracing::info!(file = %Hex(data![file]), "step 3: kernel!filp_close()");

            inject! {
                kernel!filp_close(
                    data![file],                // filp
                    0                           // id
                )
            }
        },
        //
        // Step 4:
        // - Verify that the `filp_close()` call succeeded
        //
        {
            let return_value = registers!().rax;
            tracing::info!(return_value = %Hex(return_value), "step 4: kernel!filp_close()");

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
            let handler = KernelInjectorHandler::new(
                session,
                recipe_factory(GuestFile {
                    path: cli.path.clone(),
                    content: cli.content.clone().into_bytes(),
                    file: 0,
                    position_ptr: Va(0),
                }),
            )?;

            match cli.pid {
                Some(pid) => handler.with_pid(ProcessId(pid)),
                None => Ok(handler),
            }
        })?
        .transpose()?;

    Ok(())
}
