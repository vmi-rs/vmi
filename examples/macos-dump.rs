//! This example demonstrates how to use the VMI library to analyze a macOS
//! memory dump created by the QEMU `dump-guest-memory` command.
//!
//! The dump is paired with a JSON file that holds the system registers of
//! each vCPU, and the profile is loaded from the Kernel Debug Kit that
//! matches the kernel found in the dump.
//!
//! # Possible log output
//!
//! ```text
//! Kernel:
//! =================================================
//!     Collection Base: 0xfffffe002976c000
//!     Image Base: 0xfffffe0029770000
//!     UUID: D36225BA-FD41-3361-A406-B77B0E260801
//!     Version: Darwin Kernel Version 27.0.0: Tue Aug 11 21:00:07 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_VMAPPLE
//!     Current Process: kernel_task (PID: 0)
//! Kernel Extensions:
//! =================================================
//! Module @ 0xfffffe9936000010
//!     Base Address: 0xfffffe002988c000
//!     Size: 28824
//!     Name: com.apple.kec.Libm
//!     Load Tag: 8
//!     UUID: 4E3603E4-7BF1-3ED1-B3B6-F6FA24130C74
//!
//! ...
//!
//! Processes:
//! =================================================
//!
//! ...
//!
//! Process @ 0xfffffe230f408640, PID: 479
//!     Name: orchard-marker (orchard-marker)
//!     Parent PID: 1
//!     UID: 501, GID: 20
//!     Start Time: 1791118136
//!     Image Base: 0x0000000100b20000
//!     Architecture: Arm64
//!     Image Path: /System/Volumes/Data/private/tmp/orchard-marker
//!     Executable Path: /tmp/orchard-marker
//!     Arguments: ["/tmp/orchard-marker"]
//!     Threads (1):
//!         Thread @ 0xfffffe187b6553f0, TID: 2872
//!     Regions:
//!         Region @ 0xfffffe14ddd30680: 0x0000000100b20000-0x0000000100b24000 MemoryAccess(R | X)/MemoryAccess(R | X) Tag: 0 Mapped (Exe): /System/Volumes/Data/private/tmp/orchard-marker
//!         Region @ 0xfffffe14ddf1a3c0: 0x0000000100b24000-0x0000000100b28000 MemoryAccess(R)/MemoryAccess(R | W) Tag: 0 Mapped: /System/Volumes/Data/private/tmp/orchard-marker
//!         Region @ 0xfffffe14ddd50540: 0x0000000100b28000-0x0000000100b2c000 MemoryAccess(R)/MemoryAccess(R) Tag: 0 Mapped: /System/Volumes/Data/private/tmp/orchard-marker
//!         Region @ 0xfffffe14ddd29540: 0x0000000100b2c000-0x0000000100b34000 MemoryAccess(R | W)/MemoryAccess(R | W | X) Tag: 73 Private
//!         ...
//!         Region @ 0xfffffe14dde70bc0: 0x0000000180000000-0x00000001f6000000 MemoryAccess(R)/MemoryAccess(R) Tag: 32 Submap
//!         Region @ 0xfffffe14dde00980: 0x00000001f691c000-0x00000001f8b64000 MemoryAccess(R)/MemoryAccess(R | W) Tag: 0 Mapped: /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.25.dylddata
//!         ...
//!     User Modules:
//!         0x0000000100b20000 Size: 49152 /tmp/orchard-marker
//!         0x00000001a7c12000 Size: 6388 /usr/lib/libSystem.B.dylib
//!         0x00000001a7c0d000 Size: 20252 /usr/lib/system/libcache.dylib
//!         ...
//!     Open Files:
//!            0: Pipe
//!            1: Vnode /System/Volumes/Data/private/tmp/orchard-marker.out
//!            2: Vnode /System/Volumes/Data/private/tmp/orchard-marker.out
//!
//! ...
//! ```

use isr::cache::IsrCache;
use vmi::{
    VcpuId, VmiCore, VmiError, VmiSession, VmiState, VmiVa as _,
    arch::arm64::{Arm64, Granule16KVa47},
    driver::qemu_core_dump::VmiQemuCoreDumpDriver,
    os::{
        VmiOsMapped as _, VmiOsModule as _, VmiOsProcess as _, VmiOsRegion as _, VmiOsRegionKind,
        VmiOsThread as _, VmiOsUserModule as _,
        macos::{MacOs, MacOsExt as _, MacOsProcess},
    },
};

type Arch = Arm64<Granule16KVa47>;
type Driver = VmiQemuCoreDumpDriver<Arch>;

fn handle_error(err: VmiError) -> Result<String, VmiError> {
    match err {
        VmiError::Translation(pf) => Ok(format!("PF({pf:?})")),
        _ => Err(err),
    }
}

// Format a UUID in its canonical form.
fn format_uuid(uuid: &[u8; 16]) -> String {
    let hex = uuid
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// Enumerate loaded kernel extensions.
fn enumerate_kernel_modules(vmi: &VmiState<MacOs<Driver>>) -> Result<(), VmiError> {
    for module in vmi.os().modules()? {
        let module = module?;

        let module_va = module.va();
        let base_address = module.base_address()?; // `OSKextLoadedKextSummary.address`
        let size = module.size()?; // `OSKextLoadedKextSummary.size`
        let name = module.name()?; // `OSKextLoadedKextSummary.name`
        let load_tag = module.load_tag()?; // `OSKextLoadedKextSummary.loadTag`
        let uuid = module.uuid()?; // `OSKextLoadedKextSummary.uuid`

        println!("Module @ {module_va}");
        println!("    Base Address: {base_address}");
        println!("    Size: {size}");
        println!("    Name: {name}");
        println!("    Load Tag: {load_tag}");
        println!("    UUID: {}", format_uuid(&uuid));
    }

    Ok(())
}

// Enumerate threads of a process.
fn enumerate_threads(process: &MacOsProcess<Driver>) -> Result<(), VmiError> {
    for thread in process.threads()? {
        let thread = thread?;

        let tid = thread.thread_id()?; // `thread.thread_id`
        let object = thread.object()?; // `struct thread` pointer

        println!("        Thread @ {object}, TID: {tid}");
    }

    Ok(())
}

// Enumerate memory regions of a process.
fn enumerate_regions(process: &MacOsProcess<Driver>) -> Result<(), VmiError> {
    for region in process.regions()? {
        let region = region?;

        let region_va = region.va();
        let start = region.start()?; // `vm_map_entry.vme_start`
        let end = region.end()?; // `vm_map_entry.vme_end`
        let protection = region.protection()?; // `vm_map_entry.protection`
        let max_protection = region.max_protection()?; // `vm_map_entry.max_protection`
        let tag = region.tag()?; // `vm_map_entry.vme_alias`

        print!(
            "        Region @ {region_va}: {start}-{end} {protection:?}/{max_protection:?} Tag: {tag}"
        );

        if region.is_submap()? {
            println!(" Submap");
            continue;
        }

        let kind = match region.kind() {
            Ok(kind) => kind,
            Err(err) => {
                println!(" {}", handle_error(err)?);
                continue;
            }
        };

        match &kind {
            VmiOsRegionKind::Private => println!(" Private"),
            VmiOsRegionKind::MappedImage(mapped) => {
                let path = match mapped.path() {
                    Ok(Some(path)) => path,
                    Ok(None) => String::from("<unnamed>"),
                    Err(err) => handle_error(err)?,
                };

                println!(" Mapped (Exe): {path}");
            }
            VmiOsRegionKind::MappedData(mapped) => {
                let path = match mapped.path() {
                    Ok(Some(path)) => path,
                    Ok(None) => String::from("<unnamed>"),
                    Err(err) => handle_error(err)?,
                };

                println!(" Mapped: {path}");
            }
        }
    }

    Ok(())
}

// Enumerate images loaded by dyld into a process.
fn enumerate_user_modules(process: &MacOsProcess<Driver>) -> Result<(), VmiError> {
    for module in process.user_modules()? {
        let module = module?;

        let base_address = match module.base_address() {
            // `dyld_image_info.imageLoadAddress`
            Ok(base_address) => base_address.to_string(),
            Err(err) => handle_error(err)?,
        };

        let size = match module.size() {
            Ok(size) => size.to_string(),
            Err(err) => handle_error(err)?,
        };

        let path = match module.path() {
            // `dyld_image_info.imageFilePath`
            Ok(path) => path,
            Err(err) => handle_error(err)?,
        };

        println!("        {base_address} Size: {size} {path}");
    }

    Ok(())
}

// Enumerate open files of a process.
fn enumerate_open_files(process: &MacOsProcess<Driver>) -> Result<(), VmiError> {
    for file in process.open_files()? {
        let file = file?;

        let fd = file.fd();
        let kind = match file.kind() {
            // `fileproc.fp_glob->fg_ops->fo_type`
            Ok(kind) => format!("{kind:?}"),
            Err(err) => handle_error(err)?,
        };

        let path = match file.path() {
            Ok(Some(path)) => path,
            Ok(None) => String::new(),
            Err(err) => handle_error(err)?,
        };

        println!("        {fd:4}: {kind} {path}");
    }

    Ok(())
}

// Print information about a single process.
fn print_process(process: &MacOsProcess<Driver>) -> Result<(), VmiError> {
    let pid = process.id()?; // `proc.p_pid`
    let object = process.object()?; // `struct proc` pointer
    let name = process.name()?; // `proc.p_comm`
    let full_name = process.full_name()?; // `proc.p_name`
    let ppid = process.parent_id()?; // `proc.p_ppid`
    let uid = process.uid()?; // `proc.p_uid`
    let gid = process.gid()?; // `proc.p_gid`
    let start_time = process.start_time()?; // `proc.p_start`
    let image_base = process.image_base()?; // `proc.p_main_exec_load_addr`

    println!("Process @ {object}, PID: {pid}");
    println!("    Name: {name} ({full_name})");
    println!("    Parent PID: {ppid}");
    println!("    UID: {uid}, GID: {gid}");
    println!("    Start Time: {}", start_time.as_secs());
    println!("    Image Base: {image_base}");

    let architecture = match process.architecture() {
        Ok(architecture) => format!("{architecture:?}"),
        Err(err) => handle_error(err)?,
    };
    println!("    Architecture: {architecture}");

    let image_path = match process.image_path() {
        // `proc.p_textvp`
        Ok(Some(image_path)) => image_path,
        Ok(None) => String::from("<none>"),
        Err(err) => handle_error(err)?,
    };
    println!("    Image Path: {image_path}");

    match process.arguments() {
        Ok(arguments) => {
            println!("    Executable Path: {}", arguments.executable_path);
            println!("    Arguments: {:?}", arguments.arguments);
        }
        Err(err) => println!("    Arguments: {}", handle_error(err)?),
    }

    println!("    Threads ({}):", process.thread_count()?);
    enumerate_threads(process)?;

    println!("    Regions:");
    enumerate_regions(process)?;

    println!("    User Modules:");
    enumerate_user_modules(process)?;

    println!("    Open Files:");
    enumerate_open_files(process)?;

    Ok(())
}

// Enumerate processes in the system.
fn enumerate_processes(vmi: &VmiState<MacOs<Driver>>) -> Result<(), VmiError> {
    for process in vmi.os().processes()? {
        let process = process?;

        // Report errors of a single process and continue with the next one.
        if let Err(err) = print_process(&process) {
            println!("    Error: {err}");
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .init();

    // The arguments are the dump, the register file and an optional cache
    // directory for the profile.
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 && args.len() != 4 {
        eprintln!("Usage: {} <memory.elf> <registers.json> [cache]", args[0]);
        std::process::exit(1);
    }

    let dump_file = &args[1];
    let registers_file = &args[2];
    let cache_directory = args.get(3).map_or("cache", String::as_str);

    // Setup VMI.
    let driver = Driver::new(dump_file, registers_file)?;
    let core = VmiCore::new(driver)?;

    let registers = core.registers(VcpuId(0))?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = MacOs::find_kernel(&core, &registers)?.expect("kernel information");
    tracing::info!(
        kernel_collection_base = %kernel_info.kernel_collection_base,
        base_address = %kernel_info.base_address,
        uuid = %format_uuid(&kernel_info.uuid),
        version = %kernel_info.version,
        "Kernel information"
    );

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::new(cache_directory)?;
    let entry = isr.entry_from_darwin_version(&kernel_info.version, Some(kernel_info.uuid))?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = MacOs::<Driver>::new(&profile, &kernel_info)?;
    let session = VmiSession::new(&core, &os);

    let vmi = session.with_registers(&registers);

    println!("Kernel:");
    println!("=================================================");
    println!("    Collection Base: {}", vmi.os().kernel_collection_base());
    println!("    Image Base: {}", vmi.os().kernel_image_base()?);
    println!("    UUID: {}", format_uuid(&vmi.os().kernel_uuid()));
    println!("    Version: {}", vmi.os().kernel_information_string()?);

    let current_process = vmi.os().current_process()?;
    println!(
        "    Current Process: {} (PID: {})",
        current_process.name()?,
        current_process.id()?
    );

    println!("Kernel Extensions:");
    println!("=================================================");
    enumerate_kernel_modules(&vmi)?;

    println!("Processes:");
    println!("=================================================");
    enumerate_processes(&vmi)?;

    Ok(())
}
