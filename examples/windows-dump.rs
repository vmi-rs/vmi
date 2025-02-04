//! This example demonstrates how to use the VMI library to analyze a Windows
//! kernel dump file.

use isr::cache::{IsrCache, JsonCodec};
use vmi::{
    arch::amd64::Amd64,
    driver::kdmp::VmiKdmpDriver,
    os::{
        windows::{WindowsDirectoryObject, WindowsOs, WindowsOsExt, WindowsProcess},
        VmiOsMapped as _, VmiOsProcess as _, VmiOsRegion as _, VmiOsRegionKind, VmiOsThread as _,
    },
    VcpuId, VmiCore, VmiError, VmiSession, VmiState, VmiVa as _,
};

type Arch = Amd64;
type Driver = VmiKdmpDriver<Arch>;

fn handle_error(err: VmiError) -> Result<String, VmiError> {
    match err {
        VmiError::PageFault(pf) => Ok(format!("PF({pf:?})")),
        _ => Err(err),
    }
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
        Ok(handle_table) => handle_table,
        Err(err) => {
            tracing::error!(?err, "Failed to get handle table");
            return Ok(());
        }
    };

    let handle_table_iterator = match handle_table.iter() {
        Ok(iterator) => iterator,
        Err(err) => {
            println!(
                "Failed to get handle table iterator: {}",
                handle_error(err)?
            );
            return Ok(());
        }
    };

    // Iterate over `_HANDLE_TABLE_ENTRY` items.
    for (handle, entry) in handle_table_iterator {
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

    // Setup VMI.
    let driver = Driver::new("/root/__xdyna/MEMORY-win11.DMP")?;
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

    println!("Object Tree (root directory: {}):", root_directory.va());
    println!("=================================================");
    enumerate_directory_object(&root_directory, 0)?;

    println!("Processes:");
    println!("=================================================");
    enumerate_processes(&vmi)?;

    Ok(())
}
