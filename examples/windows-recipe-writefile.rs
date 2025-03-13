//! # [`recipe!`] example
//!
//! This example demonstrates how to write a recipe with multiple steps.
//!
//! The recipe is injected into the `explorer.exe` process and writes
//! a file to the guest.
//!
//! # Possible log output
//!
//! ```text
//! DEBUG found MZ base_address=0xfffff80002861000
//!  INFO profile already exists profile_path="cache/windows/ntkrnlmp.pdb/3844dbb920174967be7aa4a2c20430fa2/profile.json"
//!  INFO Creating VMI session
//!  INFO found explorer.exe pid=1248 object=0xfffffa80030e9060
//! DEBUG injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: thread hijacked current_tid=1932
//! DEBUG injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: recipe step index=0
//!  INFO injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: step 1: kernel32!CreateFileA() target_path="C:\\Users\\John\\Desktop\\test.txt"
//! DEBUG injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: recipe step index=1
//!  INFO injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: step 2: kernel32!WriteFile() handle=0x0000000000000000
//! DEBUG injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: recipe step index=2
//!  INFO injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: step 3: kernel32!WriteFile() number_of_bytes_written=13
//!  INFO injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: step 3: kernel32!CloseHandle() handle=0x0000000000000e08
//! DEBUG injector{vcpu=0 rip=0x0000000077c62c1a}:memory_access: recipe finished result=0x0000000000000001
//! ```

mod common;

use vmi::{
    Hex, Va, VcpuId, VmiDriver,
    arch::amd64::Amd64,
    os::{VmiOsProcess as _, windows::WindowsOs},
    utils::injector::{InjectorHandler, Recipe, RecipeControlFlow, recipe},
};

#[derive(Debug, Default)]
struct GuestFile {
    /// Target path in the guest to write the file.
    target_path: String,

    /// Content to write to the file.
    content: Vec<u8>,

    /// Handle to the file.
    /// Assigned in 2nd step.
    handle: u64,

    /// The number of bytes written to the file.
    /// Assigned in 2nd step and used in 3rd step.
    bytes_written_ptr: Va,
}

impl GuestFile {
    pub fn new(target_path: impl AsRef<str>, content: impl AsRef<[u8]>) -> Self {
        Self {
            target_path: target_path.as_ref().to_string(),
            content: content.as_ref().to_vec(),

            // Mutable fields.
            handle: 0,
            bytes_written_ptr: Va::default(),
        }
    }
}

/// Create a recipe to write a file to the guest.
///
/// # Equivalent C pseudo-code
///
/// ```c
/// const char* target_path = "...\\test.txt";
/// const char content[] = "...";
///
/// HANDLE handle = CreateFileA(target_path,            // lpFileName
///                             GENERIC_WRITE,          // dwDesiredAccess
///                             0,                      // dwShareMode
///                             NULL,                   // lpSecurityAttributes
///                             CREATE_ALWAYS,          // dwCreationDisposition
///                             FILE_ATTRIBUTE_NORMAL,  // dwFlagsAndAttributes
///                             NULL);                  // hTemplateFile
///
/// if (handle == INVALID_HANDLE_VALUE) {
///     printf("kernel32!CreateFileA() failed\n");
///     return;
/// }
///
/// DWORD bytes_written;
/// if (!WriteFile(handle, content, sizeof(content), &bytes_written, 0)) {
///     printf("kernel32!WriteFile() failed\n");
/// }
///
/// CloseHandle(handle);
/// ```
fn recipe_factory<Driver>(data: GuestFile) -> Recipe<Driver, WindowsOs<Driver>, GuestFile>
where
    Driver: VmiDriver<Architecture = Amd64>,
{
    recipe![
        Recipe::<_, WindowsOs<Driver>, _>::new(data),
        //
        // Step 1:
        // - Create a file
        //
        {
            tracing::info!(
                target_path = data![target_path],
                "step 1: kernel32!CreateFileA()"
            );

            const GENERIC_WRITE: u64 = 0x40000000;
            const CREATE_ALWAYS: u64 = 2;
            const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;

            inject! {
                kernel32!CreateFileA(
                    &data![target_path],        // lpFileName
                    GENERIC_WRITE,              // dwDesiredAccess
                    0,                          // dwShareMode
                    0,                          // lpSecurityAttributes
                    CREATE_ALWAYS,              // dwCreationDisposition
                    FILE_ATTRIBUTE_NORMAL,      // dwFlagsAndAttributes
                    0                           // hTemplateFile
                )
            }
        },
        //
        // Step 2:
        // - Verify the file handle
        // - Write the content to the file
        //
        {
            let return_value = registers!().rax;

            const INVALID_HANDLE_VALUE: u64 = 0xffff_ffff_ffff_ffff;

            if return_value == INVALID_HANDLE_VALUE {
                tracing::error!(
                    return_value = %Hex(return_value),
                    "step 2: kernel32!CreateFileA() failed"
                );

                return Ok(RecipeControlFlow::Break);
            }

            tracing::info!(
                handle = %Hex(data![handle]),
                "step 2: kernel32!WriteFile()"
            );

            // Save the handle.
            data![handle] = return_value;

            // Allocate a value on the stack to store the output parameter.
            data![bytes_written_ptr] = copy_to_stack!(0u64)?;

            inject! {
                kernel32!WriteFile(
                    data![handle],              // hFile
                    data![content],             // lpBuffer
                    data![content].len(),       // nNumberOfBytesToWrite
                    data![bytes_written_ptr],   // lpNumberOfBytesWritten
                    0                           // lpOverlapped
                )
            }
        },
        //
        // Step 3:
        // - Verify that the `WriteFile()` call succeeded
        // - Close the file handle
        //
        {
            let return_value = registers!().rax;

            // Check if the `WriteFile()` call failed.
            if return_value == 0 {
                tracing::error!(
                    return_value = %Hex(return_value),
                    "step 3: kernel32!WriteFile() failed"
                );

                // Don't exit, we want to close the handle.
                // return Ok(RecipeControlFlow::Break);
            }

            // Read the number of bytes written.
            let number_of_bytes_written = vmi!().read_u32(data![bytes_written_ptr])?;
            tracing::info!(number_of_bytes_written, "step 3: kernel32!WriteFile()");

            tracing::info!(
                handle = %Hex(data![handle]),
                "step 3: kernel32!CloseHandle()"
            );

            inject! {
                kernel32!CloseHandle(
                    data![handle]               // hObject
                )
            }
        },
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (session, profile) = common::create_vmi_session()?;

    let explorer_pid = {
        // This block is used to drop the pause guard after the PID is found.
        // If the `session.handle()` would be called with the VM paused, no
        // events would be triggered.
        let _pause_guard = session.pause_guard()?;

        let registers = session.registers(VcpuId(0))?;
        let vmi = session.with_registers(&registers);

        let explorer = match common::find_process(&vmi, "explorer.exe")? {
            Some(explorer) => explorer,
            None => {
                tracing::error!("explorer.exe not found");
                return Ok(());
            }
        };

        tracing::info!(
            pid = %explorer.id()?,
            object = %explorer.object()?,
            "found explorer.exe"
        );

        explorer.id()?
    };

    session.handle(|session| {
        InjectorHandler::new(
            session,
            &profile,
            explorer_pid,
            recipe_factory(GuestFile::new(
                "C:\\Users\\John\\Desktop\\test.txt",
                "Hello, World!".as_bytes(),
            )),
        )
    })?;

    Ok(())
}
