//! This example demonstrates how to use the VMI library to analyze a Windows
//! kernel dump file.
//!
//! # Possible log output
//!
//! ```text
//! Kernel Modules:
//! =================================================
//! Module @ 0xffffd486baa62b80
//!     Base Address: 0xfffff8016e80f000
//!     Size: 17068032
//!     Name: ntoskrnl.exe
//!     Full Name: \SystemRoot\system32\ntoskrnl.exe
//! Module @ 0xffffd486baa77050
//!     Base Address: 0xfffff8016fa00000
//!     Size: 24576
//!     Name: hal.dll
//!     Full Name: \SystemRoot\system32\hal.dll
//! Module @ 0xffffd486baa77200
//!     Base Address: 0xfffff8016fa10000
//!     Size: 45056
//!     Name: kdcom.dll
//!     Full Name: \SystemRoot\system32\kd.dll
//!
//! ...
//!
//! Object Tree (root directory: 0xffffbe8b62c7ae10):
//! =================================================
//! Mutant: \PendingRenameMutex (Object: 0xffffd486bb6d6bd0)
//! Directory: \ObjectTypes (Object: 0xffffbe8b62c900a0)
//!     Type: \ObjectTypes\TmTm (Object: 0xffffd486bab8a220)
//!     Type: \ObjectTypes\CpuPartition (Object: 0xffffd486baabdda0)
//!     Type: \ObjectTypes\Desktop (Object: 0xffffd486baabc220)
//!
//! ...
//!
//! Process @ 0xffffd486be782080, PID: 1244
//!     Name: svchost.exe
//!     Session: 0
//!     Threads:
//!         Thread @ 0xffffd486be789080, TID: 1248
//!         Thread @ 0xffffd486be7f0080, TID: 1464
//!         Thread @ 0xffffd486be7ef080, TID: 1504
//!         Thread @ 0xffffd486be81f040, TID: 1548
//!         Thread @ 0xffffd486c0129080, TID: 4896
//!         Thread @ 0xffffd486bfc52080, TID: 4876
//!         Thread @ 0xffffd486bfcf5080, TID: 6832
//!         Thread @ 0xffffd486bf57b080, TID: 3920
//!         Thread @ 0xffffd486c0487080, TID: 6468
//!         Thread @ 0xffffd486c012d080, TID: 4312
//!     Regions:
//!         Region @ 0xffffd486be7260d0: 0x000000007ffe0000-0x000000007ffe1000 MemoryAccess(R) Private
//!         Region @ 0xffffd486be726260: 0x000000fb1a220000-0x000000fb1a2a0000 MemoryAccess(R | W) Private
//!         ...
//!         Region @ 0xffffd486be6f92f0: 0x00007ffa62cf0000-0x00007ffa62e9d000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\user32.dll
//!         Region @ 0xffffd486be7a4a30: 0x00007ffa62ea0000-0x00007ffa62f46000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\sechost.dll
//!         Region @ 0xffffd486be46e140: 0x00007ffa63190000-0x00007ffa63240000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\clbcatq.dll
//!         Region @ 0xffffd486be6be530: 0x00007ffa632b0000-0x00007ffa633c7000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\rpcrt4.dll
//!         Region @ 0xffffd486be6f87b0: 0x00007ffa63400000-0x00007ffa634a7000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\msvcrt.dll
//!         Region @ 0xffffd486be6f60f0: 0x00007ffa63d50000-0x00007ffa63f67000 MemoryAccess(R | W | X) Mapped (Exe): \Windows\System32\ntdll.dll
//!     PEB:
//!         Current Directory:    C:\Windows\system32\
//!         DLL Path:
//!         Image Path Name:      C:\Windows\system32\svchost.exe
//!         Command Line:         C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
//!     Handles:
//!         0004: Object: ffffd486be74cc60 GrantedAccess: 001f0003 Entry: 0xffffbe8b6e74d010
//!             Type: Event, Path: <no-path>
//!         0008: Object: ffffd486be74c9e0 GrantedAccess: 001f0003 Entry: 0xffffbe8b6e74d020
//!             Type: Event, Path: <no-path>
//!         000c: Object: ffffbe8b6e620900 GrantedAccess: 00000009 Entry: 0xffffbe8b6e74d030
//!             Type: Key, Path: \REGISTRY\MACHINE\SOFTWARE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS
//!         0010: Object: ffffd486be76f960 GrantedAccess: 00000804 Entry: 0xffffbe8b6e74d040
//!             Type: EtwRegistration, Path: <no-path>
//!
//! ...
//! ```

use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    arch::amd64::Amd64,
    driver::kdmp::VmiKdmpDriver,
    os::{
        windows::{WindowsDirectoryObject, WindowsOs, WindowsOsExt, WindowsProcess},
        VmiOsMapped as _, VmiOsModule as _, VmiOsProcess as _, VmiOsRegion as _, VmiOsRegionKind,
        VmiOsThread as _,
    },
    VcpuId, VmiCore, VmiError, VmiSession, VmiState, VmiVa as _,
};

type Arch = Amd64;
type Driver = VmiKdmpDriver<Arch>;

fn handle_error(err: VmiError) -> Result<String, VmiError> {
    match err {
        VmiError::Translation(pf) => Ok(format!("PF({pf:?})")),
        _ => Err(err),
    }
}

// Enumerate processes in the system.
fn enumerate_kernel_modules(vmi: &VmiState<Driver, WindowsOs<Driver>>) -> Result<(), VmiError> {
    for module in vmi.os().modules()? {
        let module = module?;

        let module_va = module.va();
        let base_address = module.base_address()?; // `KLDR_DATA_TABLE_ENTRY.DllBase`
        let size = module.size()?; // `KLDR_DATA_TABLE_ENTRY.SizeOfImage`
        let name = module.name()?; // `KLDR_DATA_TABLE_ENTRY.BaseDllName`
        let full_name = match module.full_name() {
            // `KLDR_DATA_TABLE_ENTRY.FullDllName`
            Ok(full_name) => full_name,
            Err(err) => handle_error(err)?,
        };

        println!("Module @ {module_va}");
        println!("    Base Address: {base_address}");
        println!("    Size: {size}");
        println!("    Name: {name}");
        println!("    Full Name: {full_name}");
    }

    Ok(())
}

// Enumerate entries in a `_OBJECT_DIRECTORY`.
fn enumerate_directory_object(
    directory_object: &WindowsDirectoryObject<Driver>,
    level: usize,
) -> Result<(), VmiError> {
    for object in directory_object.iter()? {
        // Print the indentation.
        for _ in 0..level {
            print!("    ");
        }

        // Retrieve the `_OBJECT_DIRECTORY_ENTRY.Object`.
        let object = match object {
            Ok(object) => object,
            Err(err) => {
                println!("{}", handle_error(err)?);
                continue;
            }
        };

        let object_va = object.va();

        // Determine the object type.
        let type_kind = match object.type_kind() {
            Ok(Some(typ)) => format!("{typ:?}"),
            Ok(None) => String::from("<unknown>"),
            Err(err) => handle_error(err)?,
        };

        print!("{type_kind}: ");

        // Retrieve the full name of the object.
        let name = match object.full_path() {
            Ok(Some(name)) => name,
            Ok(None) => String::from("<unnamed>"),
            Err(err) => handle_error(err)?,
        };

        println!("{name} (Object: {object_va})");

        // If the entry is a directory, recursively enumerate it.
        if let Ok(Some(next)) = object.as_directory() {
            enumerate_directory_object(&next, level + 1)?;
        }
    }

    Ok(())
}

// Enumerate entries in a `_HANDLE_TABLE`.
fn enumerate_handle_table(process: &WindowsProcess<Driver>) -> Result<(), VmiError> {
    const OBJ_PROTECT_CLOSE: u32 = 0x00000001;
    const OBJ_INHERIT: u32 = 0x00000002;
    const OBJ_AUDIT_OBJECT_CLOSE: u32 = 0x00000004;

    static LABEL_PROTECTED: [&str; 2] = ["", " (Protected)"];
    static LABEL_INHERIT: [&str; 2] = ["", " (Inherit)"];
    static LABEL_AUDIT: [&str; 2] = ["", " (Audit)"];

    // Get the handle table from `_EPROCESS.ObjectTable`.
    let handle_table = match process.handle_table() {
        Ok(Some(handle_table)) => handle_table,
        Ok(None) => {
            println!("        (No handle table)");
            return Ok(());
        }
        Err(err) => {
            tracing::error!(?err, "Failed to get handle table");
            return Ok(());
        }
    };

    // Iterate over `_HANDLE_TABLE_ENTRY` items.
    for handle_entry in handle_table.iter()? {
        let (handle, entry) = match handle_entry {
            Ok(entry) => entry,
            Err(err) => {
                println!("Failed to get handle entry: {}", handle_error(err)?);
                continue;
            }
        };

        let attributes = match entry.attributes() {
            Ok(attributes) => attributes,
            Err(err) => {
                println!("Failed to get attributes: {}", handle_error(err)?);
                continue;
            }
        };

        let granted_access = match entry.granted_access() {
            Ok(granted_access) => granted_access,
            Err(err) => {
                println!("Failed to get granted access: {}", handle_error(err)?);
                continue;
            }
        };

        let object = match entry.object() {
            Ok(Some(object)) => object,
            Ok(None) => {
                // [`WindowsHandleTable::iter`] should only return entries with
                // valid objects, so this should not happen.
                println!("<NULL>");
                continue;
            }
            Err(err) => {
                println!("Failed to get object: {}", handle_error(err)?);
                continue;
            }
        };

        let type_name = match object.type_name() {
            Ok(type_name) => type_name,
            Err(err) => handle_error(err)?,
        };

        let full_path = match object.full_path() {
            Ok(Some(path)) => path,
            Ok(None) => String::from("<no-path>"),
            Err(err) => handle_error(err)?,
        };

        println!(
            "        {:04x}: Object: {:x} GrantedAccess: {:08x}{}{}{} Entry: {}",
            handle,
            object.va().0,
            granted_access,
            LABEL_PROTECTED[((attributes & OBJ_PROTECT_CLOSE) != 0) as usize],
            LABEL_INHERIT[((attributes & OBJ_INHERIT) != 0) as usize],
            LABEL_AUDIT[((attributes & OBJ_AUDIT_OBJECT_CLOSE) != 0) as usize],
            entry.va(),
        );

        println!("            Type: {type_name}, Path: {full_path}");
    }

    Ok(())
}

// Enumerate VADs in a process.
fn enumerate_regions(process: &WindowsProcess<Driver>) -> Result<(), VmiError> {
    for region in process.regions()? {
        let region = region?;

        let region_va = region.va();
        let start = region.start()?;
        let end = region.end()?;
        let protection = region.protection()?;
        let kind = region.kind()?;

        print!("        Region @ {region_va}: {start}-{end} {protection:?}");

        match &kind {
            VmiOsRegionKind::Private => println!(" Private"),
            VmiOsRegionKind::MappedImage(mapped) => {
                let path = match mapped.path() {
                    Ok(Some(path)) => path,
                    Ok(None) => String::from("<Pagefile>"),
                    Err(err) => handle_error(err)?,
                };

                println!(" Mapped (Exe): {path}");
            }
            VmiOsRegionKind::MappedData(mapped) => {
                let path = match mapped.path() {
                    Ok(Some(path)) => path,
                    Ok(None) => String::from("<Pagefile>"),
                    Err(err) => handle_error(err)?,
                };

                println!(" Mapped: {path}");
            }
        }
    }

    Ok(())
}

// Enumerate threads in a process.
fn enumerate_threads(process: &WindowsProcess<Driver>) -> Result<(), VmiError> {
    for thread in process.threads()? {
        let thread = thread?;

        let tid = thread.id()?;
        let object = thread.object()?;

        println!("        Thread @ {object}, TID: {tid}");
    }

    Ok(())
}

// Print process information in a `_PEB.ProcessParameters`.
fn print_process_parameters(process: &WindowsProcess<Driver>) -> Result<(), VmiError> {
    let parameters = match process.peb()?.process_parameters() {
        Ok(parameters) => parameters,
        Err(err) => {
            println!("Failed to get process parameters: {}", handle_error(err)?);
            return Ok(());
        }
    };

    let current_directory = match parameters.current_directory() {
        Ok(current_directory) => current_directory,
        Err(err) => handle_error(err)?,
    };

    let dll_path = match parameters.dll_path() {
        Ok(dll_path) => dll_path,
        Err(err) => handle_error(err)?,
    };

    let image_path_name = match parameters.image_path_name() {
        Ok(image_path_name) => image_path_name,
        Err(err) => handle_error(err)?,
    };

    let command_line = match parameters.command_line() {
        Ok(command_line) => command_line,
        Err(err) => handle_error(err)?,
    };

    println!("        Current Directory:    {current_directory}");
    println!("        DLL Path:             {dll_path}");
    println!("        Image Path Name:      {image_path_name}");
    println!("        Command Line:         {command_line}");

    Ok(())
}

// Enumerate processes in the system.
fn enumerate_processes(vmi: &VmiState<Driver, WindowsOs<Driver>>) -> Result<(), VmiError> {
    for process in vmi.os().processes()? {
        let process = process?;

        let pid = process.id()?; // `_EPROCESS.UniqueProcessId`
        let object = process.object()?; // `_EPROCESS` pointer
        let name = process.name()?; // `_EPROCESS.ImageFileName`
        let session = process.session()?; // `_EPROCESS.Session`

        println!("Process @ {object}, PID: {pid}");
        println!("    Name: {name}");
        if let Some(session) = session {
            println!("    Session: {}", session.id()?); // `_MM_SESSION_SPACE.SessionId`
        }

        println!("    Threads:");
        enumerate_threads(&process)?;

        println!("    Regions:");
        enumerate_regions(&process)?;

        println!("    PEB:");
        print_process_parameters(&process)?;

        println!("    Handles:");
        enumerate_handle_table(&process)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .init();

    // First argument is the path to the dump file.
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("Usage: {} <dump-file>", args[0]);
        std::process::exit(1);
    }

    let dump_file = &args[1];

    // Setup VMI.
    let driver = Driver::new(dump_file)?;
    let core = VmiCore::new(driver)?;

    let registers = core.registers(VcpuId(0))?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = WindowsOs::find_kernel(&core, &registers)?.expect("kernel information");
    tracing::info!(?kernel_info, "Kernel information");

    // Load the profile.
    // The profile contains offsets to kernel functions and data structures.
    let isr = IsrCache::<JsonCodec>::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("Creating VMI session");
    let os = WindowsOs::<Driver>::with_kernel_base(&profile, kernel_info.base_address)?;
    let session = VmiSession::new(&core, &os);

    let vmi = session.with_registers(&registers);
    let root_directory = vmi.os().object_root_directory()?;

    println!("Kernel Modules:");
    println!("=================================================");
    enumerate_kernel_modules(&vmi)?;

    println!("Object Tree (root directory: {}):", root_directory.va());
    println!("=================================================");
    enumerate_directory_object(&root_directory, 0)?;

    println!("Processes:");
    println!("=================================================");
    enumerate_processes(&vmi)?;

    Ok(())
}
