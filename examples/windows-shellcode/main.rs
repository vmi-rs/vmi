//! Runs the `msgbox` and `kernel-file` shellcodes through VMI.
//!
//! Each subcommand selects a recipe and waits for its final bridge output:
//!
//! |   subcommand   |             recipe              |      shellcode runs on       |
//! |----------------|---------------------------------|------------------------------|
//! | `user-call`    | `user_shellcode_call_recipe`    | hijacked user-mode thread    |
//! | `user-spawn`   | `user_shellcode_spawn_recipe`   | new guest thread             |
//! | `kernel-call`  | `kernel_shellcode_call_recipe`  | hijacked thread, kernel mode |
//! | `kernel-spawn` | `kernel_shellcode_spawn_recipe` | new system thread            |
//!
//! The `msgbox` shellcode displays a message box.
//! The `kernel-file` shellcode creates a file and writes `hello world` to it.
//!
//! # Possible log output
//!
//! ```bash
//! cargo run --example windows-shellcode --all-features -- kernel-spawn
//! ```
//!
//! ```text
//! DEBUG found kernel image base_address=0xfffff80016600000
//!  INFO loading kernel profile codeview=CodeView { name: "ntkrnlmp.pdb", guid: "68a17faf3012b7846079aeecdbe0a583", age: 1 }
//! DEBUG found cached PE image path=cache/windows/ntkrnlmp.pdb/68a17faf3012b7846079aeecdbe0a5831/ntkrnlmp.pdb
//! DEBUG profile already exists profile_path=cache/windows/ntkrnlmp.pdb/68a17faf3012b7846079aeecdbe0a5831/profile.isr
//!  INFO creating VMI session
//!  INFO injecting kernel-file shellcode path="\\??\\C:\\Users\\John\\Desktop\\test-1789684125.txt" execution=Spawn
//! DEBUG active breakpoint inserted active=1 gfn=0x0000000000002e35 ctx=0xfffff80016835000 @ 0x00000000001aa000 view=1 global=true key=() tag="SeAccessCheck"
//! DEBUG created shadow page address=0x0000000002e35000 original_gfn=0x0000000000002e35 shadow_gfn=0x00000000001100a4 view=1
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt: thread hijacked session_id=1 current_pid=6588 current_tid=1896 filename="procexp64.exe"
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe:step{index=0}: allocating shellcode memory attempt=1 size=1240
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe:step{index=1}: writing shellcode attempt=1 guest_address=0xffff86060f368010 size=1240
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe:step{index=2}: patching shellcode thunk attempt=1 start_routine=0xffff86060f36846c parameter=0xffff86060f36848c
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe:step{index=2}: launching shellcode thread attempt=1 start_routine=0xffff86060f36846c
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe:step{index=3}: closing shellcode thread handle thread_handle=0xffffffff80001d4c
//! DEBUG injector{vcpu=0 rip=0xfffff80016835000}:interrupt:recipe: finished result=0x0000000000000000
//! DEBUG injector{vcpu=0 rip=0xfffff80016835004}:singlestep: active breakpoints removed active=0 gfn=0x0000000000002e35 view=1 breakpoints={((), AddressContext { va: 0xfffff80016835000, root: 0x00000000001aa000 }): Breakpoint { ctx: AddressContext { va: 0xfffff80016835000, root: 0x00000000001aa000 }, view: View(1), global: true, key: (), tag: "SeAccessCheck" }}
//! DEBUG injector{vcpu=3 rip=0xffff86060f368094}:hypercall:kernel_file: shellcode completed status=Status { stage: Write, kind: Success, code: 0, native_code: 0 } native_code=0x00000000
//!  INFO file written status=Status { stage: Write, kind: Success, code: 0, native_code: 0 } path="\\??\\C:\\Users\\John\\Desktop\\test-1789684125.txt"
//! ```

#[path = "../common/mod.rs"]
mod common;

mod kernel_file;
mod msgbox;

use anyhow::Error;
use clap::{Parser, Subcommand};

use crate::{kernel_file::KernelFileArguments, msgbox::MsgboxArguments};

/// Command-line interface for the `windows-shellcode` example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Command to run.
    #[command(subcommand)]
    command: Command,
}

/// Shellcode command selected on the command line.
#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the `msgbox` shellcode on the hijacked user-mode thread.
    UserCall(MsgboxArguments),

    /// Runs the `msgbox` shellcode on a new guest thread.
    UserSpawn(MsgboxArguments),

    /// Runs the `kernel-file` shellcode on the hijacked thread in kernel mode.
    KernelCall(KernelFileArguments),

    /// Runs the `kernel-file` shellcode on a new system thread.
    KernelSpawn(KernelFileArguments),
}

/// Shellcode execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Execution {
    /// Runs the shellcode on the hijacked thread.
    Call,

    /// Runs the shellcode on a new thread.
    Spawn,
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let setup = common::VmiSetup::new()?;
    let session = setup.session();

    match cli.command {
        Command::UserCall(arguments) => msgbox::run(&session, arguments, Execution::Call),
        Command::UserSpawn(arguments) => msgbox::run(&session, arguments, Execution::Spawn),
        Command::KernelCall(arguments) => kernel_file::run(&session, arguments, Execution::Call),
        Command::KernelSpawn(arguments) => kernel_file::run(&session, arguments, Execution::Spawn),
    }
}
