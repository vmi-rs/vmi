//! CLI that exercises all four shellcode execution modes over VMI.
//!
//! Each subcommand injects an `scfw` payload into a running Windows guest and
//! waits for its terminal bridge status:
//!
//! | subcommand | recipe | payload runs on |
//! |---|---|---|
//! | `user-call` | `user_shellcode_call_recipe` | hijacked user-mode thread |
//! | `user-spawn` | `user_shellcode_spawn_recipe` | new guest thread |
//! | `kernel-call` | `kernel_shellcode_call_recipe` | hijacked thread, kernel mode |
//! | `kernel-spawn` | `kernel_shellcode_spawn_recipe` | spawned system thread |
//!
//! The user-mode payload displays a message box; the kernel-mode payload
//! creates a file and writes `hello world` into it.

#[path = "../common/mod.rs"]
mod common;

mod kernel_file;
mod msgbox;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Error};
use clap::{Args, Parser, Subcommand};
use vmi::utils::{
    injector::{KernelInjectorHandler, UserInjectorHandler},
    shellcode::StatusKind,
};

use crate::{
    common::WindowsSession,
    kernel_file::{
        KernelFileBridge, KernelFileParameters, KernelFileStatus, kernel_file_call_recipe,
        kernel_file_spawn_recipe,
    },
    msgbox::{MsgboxBridge, MsgboxParameters, msgbox_call_recipe, msgbox_spawn_recipe},
};

/// Top-level command-line interface for the windows-shellcode example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Operation to run.
    #[command(subcommand)]
    command: Command,
}

/// Shellcode execution mode selected on the command line.
#[derive(Debug, Subcommand)]
enum Command {
    /// Displays a message box on the hijacked user-mode thread.
    UserCall(MsgboxArguments),

    /// Displays a message box on a newly created guest thread.
    UserSpawn(MsgboxArguments),

    /// Creates a guest file from kernel mode on the hijacked thread.
    KernelCall(KernelFileArguments),

    /// Creates a guest file from a spawned kernel-mode system thread.
    KernelSpawn(KernelFileArguments),
}

/// Command-line arguments shared by both user-mode subcommands.
#[derive(Debug, Args)]
struct MsgboxArguments {
    /// Name of the process that will display the message box.
    #[arg(long, default_value = "explorer.exe")]
    process: String,

    /// Message box title.
    #[arg(long, default_value = "Hello from VMI")]
    title: String,

    /// Message box text.
    #[arg(long, default_value = "Injected by windows-shellcode")]
    text: String,
}

/// Resolved msgbox request ready for injection.
#[derive(Debug)]
struct MsgboxRequest {
    /// Name of the process in which the msgbox shellcode runs.
    process: String,

    /// Parameters consumed by the msgbox shellcode.
    parameters: MsgboxParameters,
}

impl MsgboxArguments {
    /// Converts CLI arguments into a msgbox request.
    fn into_request(self) -> MsgboxRequest {
        MsgboxRequest {
            process: self.process,
            parameters: MsgboxParameters::new(self.title, self.text),
        }
    }
}

/// Command-line arguments shared by both kernel-mode subcommands.
#[derive(Debug, Args)]
struct KernelFileArguments {
    /// Guest path of the created file.
    ///
    /// Defaults to a timestamped file on the `John` user's desktop. A path
    /// starting with a backslash is passed through as an NT path.
    #[arg(long)]
    path: Option<String>,
}

/// Resolved kernel-file request ready for injection.
#[derive(Debug)]
struct KernelFileRequest {
    /// Parameters consumed by the kernel-file shellcode.
    parameters: KernelFileParameters,
}

impl KernelFileArguments {
    /// Converts CLI arguments into a kernel-file request.
    fn into_request(self) -> KernelFileRequest {
        KernelFileRequest {
            parameters: KernelFileParameters::new(
                self.path.unwrap_or_else(default_kernel_file_path),
            ),
        }
    }
}

/// Recipe that carries the payload into the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Execution {
    /// Calls the payload on the hijacked thread.
    Call,

    /// Spawns a thread for the payload.
    Spawn,
}

/// Returns the default kernel-file path, made unique by the current time.
fn default_kernel_file_path() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);

    format!(r"C:\Users\John\Desktop\test-{timestamp}.txt")
}

/// Validates the result returned by `MessageBoxA`.
fn validate_msgbox_result(result: u64) -> Result<u64, Error> {
    anyhow::ensure!(result != 0, "MessageBoxA failed");
    Ok(result)
}

/// Decodes and validates a terminal kernel-file status.
fn validate_kernel_file_status(packed_status: u64) -> Result<KernelFileStatus, Error> {
    let status = KernelFileStatus::decode(packed_status);
    anyhow::ensure!(
        status.kind() == StatusKind::SUCCESS,
        "kernel-file shellcode failed: {status:?}"
    );
    Ok(status)
}

/// Runs a user-mode message box injection.
fn run_msgbox(
    session: &WindowsSession,
    arguments: MsgboxArguments,
    execution: Execution,
) -> Result<(), Error> {
    let MsgboxRequest {
        process,
        parameters,
    } = arguments.into_request();

    let process_id = common::find_process_id(session, &process)?;

    tracing::info!(?execution, "injecting msgbox shellcode");

    let result = session
        .handle(|session| {
            let recipe = match execution {
                Execution::Call => msgbox_call_recipe(&parameters),
                Execution::Spawn => msgbox_spawn_recipe(&parameters),
            };

            UserInjectorHandler::new(session, recipe)?
                .with_bridge(MsgboxBridge)?
                .with_pid(process_id)
        })?
        .context("msgbox injection interrupted")?
        .context("msgbox bridge completed without a result")?
        .map_err(|packet| anyhow::anyhow!("unhandled msgbox bridge packet: {packet:?}"))?;

    let result = validate_msgbox_result(result)?;

    tracing::info!(result, "message box closed");
    Ok(())
}

/// Runs a kernel-mode file injection.
fn run_kernel_file(
    session: &WindowsSession,
    arguments: KernelFileArguments,
    execution: Execution,
) -> Result<(), Error> {
    let KernelFileRequest { parameters } = arguments.into_request();

    tracing::info!(
        path = parameters.nt_path(),
        ?execution,
        "injecting kernel-file shellcode"
    );

    let packed_status = session
        .handle(|session| {
            let recipe = match execution {
                Execution::Call => kernel_file_call_recipe(&parameters),
                Execution::Spawn => kernel_file_spawn_recipe(&parameters),
            };

            KernelInjectorHandler::new(session, recipe)?.with_bridge(KernelFileBridge)
        })?
        .context("kernel-file injection interrupted")?
        .context("kernel-file bridge completed without a result")?
        .map_err(|packet| anyhow::anyhow!("unhandled kernel-file bridge packet: {packet:?}"))?;

    let status = validate_kernel_file_status(packed_status)?;

    tracing::info!(?status, path = parameters.nt_path(), "file written");
    Ok(())
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let session = common::create_vmi_session()?;

    match cli.command {
        Command::UserCall(arguments) => run_msgbox(&session, arguments, Execution::Call),
        Command::UserSpawn(arguments) => run_msgbox(&session, arguments, Execution::Spawn),
        Command::KernelCall(arguments) => run_kernel_file(&session, arguments, Execution::Call),
        Command::KernelSpawn(arguments) => run_kernel_file(&session, arguments, Execution::Spawn),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_commands_use_defaults() {
        let cli = Cli::try_parse_from(["windows-shellcode", "user-spawn"]).unwrap();
        let Command::UserSpawn(arguments) = cli.command
        else {
            panic!("expected user-spawn command");
        };

        assert_eq!(arguments.process, "explorer.exe");
        assert_eq!(arguments.title, "Hello from VMI");
        assert_eq!(arguments.text, "Injected by windows-shellcode");
    }

    #[test]
    fn user_commands_accept_overrides() {
        let cli = Cli::try_parse_from([
            "windows-shellcode",
            "user-call",
            "--process",
            "notepad.exe",
            "--title",
            "Title",
            "--text",
            "Text",
        ])
        .unwrap();
        let Command::UserCall(arguments) = cli.command
        else {
            panic!("expected user-call command");
        };

        let request = arguments.into_request();

        assert_eq!(request.process, "notepad.exe");
        assert_eq!(request.parameters, MsgboxParameters::new("Title", "Text"));
    }

    #[test]
    fn zero_message_box_result_is_an_error() {
        assert!(validate_msgbox_result(0).is_err());
        assert_eq!(validate_msgbox_result(1).unwrap(), 1);
    }

    #[test]
    fn kernel_commands_default_to_a_timestamped_desktop_path() {
        let cli = Cli::try_parse_from(["windows-shellcode", "kernel-spawn"]).unwrap();
        let Command::KernelSpawn(arguments) = cli.command
        else {
            panic!("expected kernel-spawn command");
        };

        let request = arguments.into_request();
        let nt_path = request.parameters.nt_path();

        assert!(
            nt_path.starts_with(r"\??\C:\Users\John\Desktop\test-"),
            "unexpected default path: {nt_path}"
        );
        assert!(
            nt_path.ends_with(".txt"),
            "unexpected default path: {nt_path}"
        );
    }

    #[test]
    fn kernel_status_distinguishes_success_from_failure() {
        // Stage `Write`, kind `Success`, no error code.
        assert_eq!(
            validate_kernel_file_status(0x0000_0002).unwrap().stage(),
            crate::kernel_file::KernelFileStage::WRITE
        );

        // Stage `Create`, kind `OperationFailed`, error `zw_create_file`.
        let error = validate_kernel_file_status(0x0002_fe01).unwrap_err();
        assert!(error.to_string().contains("OperationFailed"));
    }
}
