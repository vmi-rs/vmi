//! # macOS [`recipe!`] example
//!
//! This example copies a file from the host into a macOS guest running inside
//! a KVM virtual machine on an Apple silicon host, and can launch it. No agent
//! runs in the guest.
//!
//! The recipe runs on a hijacked thread of a running process, `Finder` unless
//! `--process` names another one. It maps a buffer in that process, wires it
//! so that the host can fill it, writes it to the file and unmaps it. With
//! `--launch`, the process then starts the file with `posix_spawn` and its own
//! environment.
//!
//! The injector hijacks a thread of the process when the thread returns from
//! a syscall. When the process is idle, the injector wakes the first of its
//! threads that waits to receive a Mach message, such as the main thread of
//! `Finder` in its run loop.
//!
//! The guest is a QEMU `vmapple` machine, as in the
//! `basic-process-list-kvm-macos` example. The kernel profile is built from
//! the Kernel Debug Kit that matches the guest kernel.
//!
//! # Possible log output
//!
//! ```bash
//! RUST_LOG=info,vmi_utils=debug cargo run --release --example macos-recipe-deploy-kvm \
//!     --features arch-arm64,driver-kvm,os-macos,utils -- \
//!     deploy-test.sh /Users/john/vmi-deploy-test.sh --launch
//! ```
//!
//! ```text
//!  INFO kernel information version=Darwin Kernel Version 27.0.0: Tue Aug 11 21:00:07 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_VMAPPLE
//!  INFO creating VMI session
//!  INFO found process pid=434 object=0xfffffe2520e23190 name="Finder"
//! DEBUG injector{vcpu=1 pc=0xfffffe0013afd244}: waking thread pid=434 thread=0xfffffe1e5170dec0 ip_va=0x000000019708cc20
//! DEBUG injector{vcpu=0 pc=0xfffffe0014277430}:kernel_injector{vcpu=0 pc=0xfffffe0014277430}:breakpoint: kernel thread hijacked current_pid=1074 thread=0xfffffe1e50066710 name="XProtectRemediat"
//! DEBUG injector{vcpu=0 pc=0xfffffe0014277430}:kernel_injector{vcpu=0 pc=0xfffffe0014277430}:breakpoint:recipe:step{index=5}: wake: thread_abort_safely thread_id=2653 result=0x0000000000000000
//! DEBUG injector{vcpu=0 pc=0xfffffe0014277430}:kernel_injector{vcpu=0 pc=0xfffffe0014277430}:breakpoint:recipe: finished result=0xfffffe1e5170dec0
//! DEBUG injector{vcpu=3 pc=0x000000019708cc20}:memory_access: thread hijacked current_pid=434 thread_id=2653 name="Finder"
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=0}: step 1: mmap() size=104
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=1}: step 2: mlock() buffer=0x0000000106094000
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=2}: step 3: creat() path="/Users/john/vmi-deploy-test.sh" mode=755
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=3}: step 4: write() fd=3
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=4}: step 5: close() written=104
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=5}: step 6: munmap() buffer=0x0000000106094000
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=6}: step 7: _NSGetEnviron()
//!  INFO injector{vcpu=3 pc=0x000000019708cc20}:memory_access:recipe:step{index=7}: step 8: posix_spawn() path="/Users/john/vmi-deploy-test.sh"
//!  INFO injector{vcpu=0 pc=0x000000019708cc20}:memory_access:recipe:step{index=8}: step 9: launched pid=1076
//! DEBUG injector{vcpu=0 pc=0x000000019708cc20}:memory_access:recipe: finished result=0x0000000000000000
//! ```

// The KVM driver introspects arm64 guests only on aarch64 hosts. On other
// hosts, the example builds to a stub that reports this.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

use std::{
    os::fd::AsFd,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context as _, Error};
use clap::Parser;
use isr::cache::IsrCache;
use vmi::{
    Registers as _, Va, VcpuId, VmiCore, VmiSession,
    arch::arm64::{Arm64, Granule16KVa47},
    driver::{VmiFullDriver, kvm::VmiKvmDriver},
    os::{VmiOsProcess as _, macos::MacOs},
    utils::injector::{ArchAdapter, Recipe, RecipeControlFlow, UserInjectorHandler, recipe},
};

/// Architecture of the guest.
type Arch = Arm64<Granule16KVa47>;

/// VMI driver of the guest.
type KvmDriver = VmiKvmDriver<Arch>;

/// Pages can be read, `PROT_READ` in `<sys/mman.h>`.
const PROT_READ: u64 = 0x01;

/// Pages can be written, `PROT_WRITE` in `<sys/mman.h>`.
const PROT_WRITE: u64 = 0x02;

/// Changes are private, `MAP_PRIVATE` in `<sys/mman.h>`.
const MAP_PRIVATE: u64 = 0x0002;

/// Memory is not backed by a file, `MAP_ANON` in `<sys/mman.h>`.
const MAP_ANON: u64 = 0x1000;

/// Result of a failed `mmap`, `MAP_FAILED` in `<sys/mman.h>`.
const MAP_FAILED: u64 = u64::MAX;

/// Index of the step that unmaps the buffer, where a failed step jumps.
const STEP_UNMAP_BUFFER: usize = 5;

/// Command-line interface for the `macos-recipe-deploy-kvm` example.
#[derive(Debug, Parser)]
struct Cli {
    /// File on the host to copy into the guest.
    source: PathBuf,

    /// Absolute path of the file in the guest.
    destination: String,

    /// Launches the file once it is written, with permissions 0755 instead
    /// of 0644.
    #[arg(long)]
    launch: bool,

    /// Name of the guest process whose thread runs the recipe.
    #[arg(long, default_value = "Finder")]
    process: String,

    /// Pid of the QEMU process, or the first `qemu-system` process.
    #[arg(long)]
    qemu_pid: Option<i32>,

    /// Directory of the profile cache.
    #[arg(long, default_value = "cache")]
    cache: PathBuf,
}

/// State shared by the recipe steps.
#[derive(Debug, Default)]
struct GuestFile {
    /// Path of the file in the guest.
    path: String,

    /// Content of the file.
    content: Vec<u8>,

    /// Permissions of the file when it is created.
    mode: u64,

    /// Whether the file is launched once it is written.
    launch: bool,

    /// Guest buffer that holds the content.
    /// Assigned in the 2nd step.
    buffer: Va,

    /// File descriptor of the file.
    /// Assigned in the 4th step.
    fd: u64,

    /// Number of bytes written to the file.
    /// Updated in the 5th step.
    written: u64,

    /// Whether a step failed, after which the steps only clean up.
    failed: bool,

    /// Guest address that receives the process ID of the launched file.
    /// Assigned in the 8th step.
    pid_ptr: Va,
}

impl GuestFile {
    /// Creates the state of a file to write to `path`.
    fn new(path: impl AsRef<str>, content: Vec<u8>, launch: bool) -> Self {
        Self {
            path: path.as_ref().to_string(),
            content,
            mode: if launch { 0o755 } else { 0o644 },
            launch,
            ..Self::default()
        }
    }
}

/// Creates a recipe that writes a file to the guest and can launch it.
///
/// # Equivalent C pseudo-code
///
/// ```c
/// const char *path = "...";
/// const char content[] = "...";
///
/// void *buffer = mmap(NULL, sizeof(content), PROT_READ | PROT_WRITE,
///                     MAP_PRIVATE | MAP_ANON, -1, 0);
/// if (buffer == MAP_FAILED)
///     return;
///
/// if (mlock(buffer, sizeof(content)) == 0) {
///     memcpy(buffer, content, sizeof(content));   // by the host
///
///     int fd = creat(path, launch ? 0755 : 0644);
///     if (fd >= 0) {
///         for (size_t written = 0; written < sizeof(content); ) {
///             ssize_t result = write(fd, buffer + written,
///                                    sizeof(content) - written);
///             if (result <= 0)
///                 break;
///             written += result;
///         }
///
///         close(fd);
///     }
/// }
///
/// munmap(buffer, sizeof(content));
///
/// if (launch) {
///     char *argv[] = { (char *)path, NULL };
///     pid_t pid;
///
///     posix_spawn(&pid, path, NULL, NULL, argv, *_NSGetEnviron());
/// }
/// ```
fn recipe_factory<Driver>(data: GuestFile) -> Recipe<MacOs<Driver>, GuestFile>
where
    Driver: VmiFullDriver<Architecture = Arch>,
{
    recipe![
        Recipe::<MacOs<Driver>>::new(data),
        //
        // Step 1:
        // - Map a buffer for the content
        //
        {
            tracing::info!(size = data![content].len(), "step 1: mmap()");

            inject! {
                "libsystem_kernel.dylib"!_mmap(
                    0,                          // addr
                    data![content].len(),       // len
                    PROT_READ | PROT_WRITE,     // prot
                    MAP_PRIVATE | MAP_ANON,     // flags
                    -1,                         // fd
                    0                           // offset
                )
            }
        },
        //
        // Step 2:
        // - Verify the buffer
        // - Wire the buffer, so that its pages stay resident while the host
        //   fills them
        //
        {
            let buffer = registers!().result();
            if buffer == MAP_FAILED {
                tracing::error!("step 2: mmap() failed");
                return Ok(RecipeControlFlow::Break);
            }

            data![buffer] = Va(buffer);
            tracing::info!(buffer = %data![buffer], "step 2: mlock()");

            inject! {
                "libsystem_kernel.dylib"!_mlock(
                    data![buffer],              // addr
                    data![content].len()        // len
                )
            }
        },
        //
        // Step 3:
        // - Verify the wiring
        // - Copy the content into the buffer
        // - Create the file
        //
        {
            if registers!().result() != 0 {
                tracing::error!("step 3: mlock() failed");
                data![failed] = true;
                return Ok(RecipeControlFlow::Goto(STEP_UNMAP_BUFFER));
            }

            vmi!().write(data![buffer], &data![content])?;

            tracing::info!(path = data![path], mode = %format!("{:o}", data![mode]), "step 3: creat()");

            inject! {
                "libsystem_c.dylib"!_creat(
                    &data![path],               // path
                    data![mode]                 // mode
                )
            }
        },
        //
        // Step 4:
        // - Verify the file descriptor
        // - Write the content to the file
        //
        {
            let fd = registers!().result() as i32;
            if fd < 0 {
                tracing::error!("step 4: creat() failed");
                data![failed] = true;
                return Ok(RecipeControlFlow::Goto(STEP_UNMAP_BUFFER));
            }

            data![fd] = fd as u64;
            tracing::info!(fd, "step 4: write()");

            inject! {
                "libsystem_kernel.dylib"!_write(
                    data![fd],                  // fildes
                    data![buffer],              // buf
                    data![content].len()        // nbyte
                )
            }
        },
        //
        // Step 5:
        // - Verify the write
        // - Write the rest of the content, and repeat this step
        // - Close the file once all of the content is written
        //
        {
            let result = registers!().result() as i64;
            if result <= 0 {
                tracing::error!(result, "step 5: write() failed");
                data![failed] = true;
            }
            else {
                data![written] += result as u64;
            }

            let remaining = data![content].len() as u64 - data![written];
            if !data![failed] && remaining > 0 {
                tracing::info!(written = data![written], remaining, "step 5: write()");

                inject! {
                    "libsystem_kernel.dylib"!_write(
                        data![fd],                      // fildes
                        data![buffer] + data![written], // buf
                        remaining                       // nbyte
                    )
                }?;

                return Ok(RecipeControlFlow::Repeat);
            }

            tracing::info!(written = data![written], "step 5: close()");

            inject! {
                "libsystem_kernel.dylib"!_close(
                    data![fd]                   // fildes
                )
            }
        },
        //
        // Step 6 (`STEP_UNMAP_BUFFER`):
        // - Unmap the buffer
        //
        {
            tracing::info!(buffer = %data![buffer], "step 6: munmap()");

            inject! {
                "libsystem_kernel.dylib"!_munmap(
                    data![buffer],              // addr
                    data![content].len()        // len
                )
            }
        },
        //
        // Step 7:
        // - Finish, unless the file is to be launched
        // - Get the environment of the process
        //
        {
            if data![failed] || !data![launch] {
                return Ok(RecipeControlFlow::Break);
            }

            tracing::info!("step 7: _NSGetEnviron()");

            inject! {
                "libsystem_c.dylib"!__NSGetEnviron()
            }
        },
        //
        // Step 8:
        // - Launch the file
        //
        {
            let environ = vmi!().read_va_native(Va(registers!().result()))?;

            let mut path = data![path].clone().into_bytes();
            path.push(0);

            let path = <Arch as ArchAdapter<Driver>>::copy_bytes_to_stack(
                vmi!(),
                registers!(),
                &path,
                16,
            )?;
            let argv = copy_to_stack!([path.0, 0u64])?;
            data![pid_ptr] = copy_to_stack!(0u32)?;

            tracing::info!(path = data![path], "step 8: posix_spawn()");

            inject! {
                "libsystem_kernel.dylib"!_posix_spawn(
                    data![pid_ptr],             // pid
                    path,                       // path
                    0,                          // file_actions
                    0,                          // attrp
                    argv,                       // argv
                    environ                     // envp
                )
            }
        },
        //
        // Step 9:
        // - Verify the launch
        //
        {
            let result = registers!().result();
            if result != 0 {
                tracing::error!(errno = result, "step 9: posix_spawn() failed");
                return Ok(RecipeControlFlow::Break);
            }

            let pid = vmi!().read_u32(data![pid_ptr])?;
            tracing::info!(pid, "step 9: launched");

            Ok(RecipeControlFlow::Break)
        },
    ]
}

/// Scans `/proc` for the first running `qemu-system` process and returns its
/// pid.
fn find_qemu_pid() -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let pid = match entry.file_name().to_string_lossy().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim_end().starts_with("qemu-system") {
            return Some(pid);
        }
    }

    None
}

#[cfg(target_arch = "aarch64")]
fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let content = std::fs::read(&cli.source)
        .with_context(|| format!("failed to read {}", cli.source.display()))?;
    anyhow::ensure!(!content.is_empty(), "{} is empty", cli.source.display());

    let qemu_pid = match cli.qemu_pid {
        Some(qemu_pid) => qemu_pid,
        None => find_qemu_pid().context("no qemu-system process found")?,
    };

    // Ctrl-C makes the session abort the recipe and restore the hijacked
    // thread instead of ending the program at once.
    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate)?;

    // Duplicate QEMU's KVM fds and create the VMI driver.
    let fds = kvm::attach::from_pid(qemu_pid)?;
    let driver = KvmDriver::new(fds.vm.as_fd(), fds.vcpus)?;
    let core = VmiCore::new(driver)?;

    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;
        MacOs::find_kernel(&core, &registers)?.context("kernel not found")?
    };
    tracing::info!(version = %kernel_info.version, "kernel information");

    let isr = IsrCache::new(&cli.cache)?;
    let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
    let profile = entry.profile()?;

    tracing::info!("creating VMI session");
    let os = MacOs::<KvmDriver>::new(&profile, &kernel_info)?;
    let session = VmiSession::new(&core, &os);

    let pid = {
        // This block drops the pause guard once the process is found. Events
        // are not delivered while the VM is paused.
        let paused = session.pause_guard()?;
        let vmi = paused.state();

        let process = vmi
            .os()
            .find_process(cli.process.as_str())?
            .with_context(|| format!("{} not found", cli.process))?;

        tracing::info!(
            pid = %process.id()?,
            object = %process.object()?,
            name = cli.process,
            "found process"
        );

        process.id()?
    };

    session
        .handle(|session| {
            UserInjectorHandler::new(
                session,
                recipe_factory(GuestFile::new(&cli.destination, content, cli.launch)),
            )?
            .with_pid(pid)
        })?
        .transpose()?;

    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("The KVM driver introspects arm64 guests only on aarch64 hosts.");
}
