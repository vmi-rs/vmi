//! CLI that drives the deploy shellcode recipe, its host-side policy gates and
//! the post-execution monitor into a Windows guest over VMI.

#[path = "../common/mod.rs"]
mod common;

mod deploy;
mod file_transfer;
mod monitor;

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context as _, Error};
use clap::{Args, Parser, Subcommand};
use isr::Profile;
use vmi::utils::{injector::UserInjectorHandler, shellcode::StatusKind};

use crate::{
    common::WindowsSession,
    deploy::{
        DeployBridge, DeployParameters, DeployPolicy, DeployStage, DeployStatus, ExecuteResponse,
        deploy_recipe,
    },
    monitor::{Monitor, MonitorOutput},
};

/// Top-level command-line interface for the windows-bridge example.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Operation to run.
    #[command(subcommand)]
    command: Command,
}

/// Injection operation selected on the command line.
#[derive(Debug, Subcommand)]
enum Command {
    /// Downloads, extracts, or executes content in a Windows process.
    Deploy(DeployArguments),
}

/// Command-line arguments for the deploy subcommand.
#[derive(Debug, Args)]
struct DeployArguments {
    /// Name of the process in which the deploy shellcode runs.
    #[arg(long, default_value = "explorer.exe")]
    process: String,

    /// URL downloaded by the guest.
    #[arg(long, requires = "download_path")]
    url: Option<String>,

    /// Guest path to which the URL is downloaded.
    #[arg(long, requires = "url")]
    download_path: Option<String>,

    /// Guest directory into which the downloaded archive is extracted.
    #[arg(long = "extract-to", requires = "url")]
    extraction_directory: Option<String>,

    /// Guest executable launched after optional download and extraction.
    #[arg(long)]
    execute: Option<String>,

    /// Command-line arguments passed to the guest executable.
    #[arg(long, requires = "execute")]
    arguments: Option<String>,

    /// Guest working directory used for execution.
    #[arg(long, requires = "execute")]
    working_directory: Option<String>,

    /// Windows `SW_*` value used for execution.
    #[arg(long, requires = "execute")]
    show_window: Option<i32>,

    /// Monitors the launched guest executable until it terminates.
    #[arg(long, requires = "execute")]
    monitor: bool,

    /// Host directory receiving files written by the monitored process.
    #[arg(long, default_value = "artifacts")]
    output_directory: PathBuf,

    /// Number of retries allowed after a failed download attempt.
    #[arg(long, default_value_t = 0)]
    max_download_retries: u64,
}

/// Resolved monitor configuration derived from deploy CLI arguments.
#[derive(Debug)]
struct DeployMonitorRequest {
    /// Kernel process name expected for the launched executable.
    executable_name: String,

    /// Host directory receiving transferred files.
    output_directory: PathBuf,
}

/// Resolved deploy request ready for injection.
#[derive(Debug)]
struct DeployRequest {
    /// Name of the process in which the deploy shellcode runs.
    process: String,

    /// Serialized operations consumed by the deploy shellcode.
    parameters: DeployParameters,

    /// Host policy applied to deploy stage gates.
    policy: DeployPolicy,

    /// Monitor configuration when execution must be observed.
    monitor: Option<DeployMonitorRequest>,
}

impl DeployArguments {
    /// Converts CLI arguments into a deploy request.
    fn into_request(self) -> Result<DeployRequest, Error> {
        let Self {
            process,
            url,
            download_path,
            extraction_directory,
            execute,
            arguments,
            working_directory,
            show_window,
            monitor,
            max_download_retries,
            output_directory,
        } = self;

        let policy = DeployPolicy::default().max_download_retries(max_download_retries);
        let policy = if monitor {
            policy.execute_response(ExecuteResponse::Wait)
        }
        else {
            policy.maybe_allow_execute(execute.is_some())
        };

        let monitor_request = if monitor {
            let executable = execute
                .as_deref()
                .context("--execute required by clap when --monitor is enabled")?;
            let executable_name = windows_executable_basename(executable)
                .with_context(|| format!("`--execute {executable}` has no basename"))?
                .to_owned();

            Some(DeployMonitorRequest {
                executable_name,
                output_directory,
            })
        }
        else {
            None
        };

        let parameters = match (url, execute) {
            (None, None) => DeployParameters::builder().build(),
            (None, Some(executable)) => DeployParameters::builder()
                .execute(executable)
                .maybe_arguments(arguments)
                .maybe_working_directory(working_directory)
                .maybe_show_window(show_window)
                .build(),
            (Some(url), None) => {
                let download_path =
                    download_path.context("--download-path required by clap when --url is set")?;

                DeployParameters::builder()
                    .download(url)
                    .download_path(download_path)
                    .maybe_extraction_directory(extraction_directory)
                    .build()
            }
            (Some(url), Some(executable)) => {
                let download_path =
                    download_path.context("--download-path required by clap when --url is set")?;

                DeployParameters::builder()
                    .download(url)
                    .download_path(download_path)
                    .maybe_extraction_directory(extraction_directory)
                    .execute(executable)
                    .maybe_arguments(arguments)
                    .maybe_working_directory(working_directory)
                    .maybe_show_window(show_window)
                    .build()
            }
        };

        Ok(DeployRequest {
            process,
            parameters,
            policy,
            monitor: monitor_request,
        })
    }
}

/// Returns the final component of a path using Windows path separators.
fn windows_executable_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

/// Decodes and validates a terminal deploy status.
fn validate_deploy_status(packed_status: u64) -> Result<DeployStatus, Error> {
    let status = DeployStatus::decode(packed_status);
    anyhow::ensure!(
        status.kind() == StatusKind::SUCCESS,
        "deploy failed: {status:?}"
    );
    Ok(status)
}

/// Validates the injector handoff used before deploy monitoring begins.
fn validate_deploy_waiting_status(packed_status: u64) -> Result<DeployStatus, Error> {
    let status = DeployStatus::decode(packed_status);
    anyhow::ensure!(
        status.stage() == DeployStage::EXECUTE
            && status.kind() == StatusKind::WAITING
            && status.code() == 0,
        "deploy monitor handoff failed: {status:?}"
    );
    Ok(status)
}

/// Resolves monitor completion when a signal interrupts the VMI wait.
fn resolve_monitor_outcome(
    outcome: Option<MonitorOutput>,
    terminated: bool,
) -> Result<MonitorOutput, Error> {
    match outcome {
        Some(outcome) => Ok(outcome),
        None if terminated => Ok(Ok(None)),
        None => anyhow::bail!("deploy monitoring interrupted"),
    }
}

/// Runs a deploy injection.
fn run_deploy(
    session: &WindowsSession,
    profile: &Profile,
    terminate_flag: Arc<AtomicBool>,
    arguments: DeployArguments,
) -> Result<(), Error> {
    let DeployRequest {
        process,
        parameters,
        policy,
        monitor,
    } = arguments.into_request()?;

    let process_id = common::find_process_id(session, &process)?;

    let result = session
        .handle(|session| {
            UserInjectorHandler::new(session, deploy_recipe(&parameters))?
                .with_bridge(DeployBridge::new(policy))?
                .with_pid(process_id)
        })?
        .context("deploy injection interrupted")?
        .context("deploy bridge completed without a result")?
        .map_err(|packet| anyhow::anyhow!("unhandled deploy bridge packet: {packet:?}"))?;

    let monitor = match monitor {
        Some(monitor) => monitor,
        None => {
            let status = validate_deploy_status(result)?;
            tracing::info!(?status, "deploy completed");
            return Ok(());
        }
    };

    let status = validate_deploy_waiting_status(result)?;
    tracing::info!(?status, "deploy injector parked at execute gate");

    let monitor_terminate_flag = terminate_flag.clone();
    let outcome = session.handle(|session| {
        Monitor::new(
            session,
            profile,
            monitor_terminate_flag,
            monitor.executable_name,
            process_id,
            monitor.output_directory,
        )
    })?;

    let outcome = resolve_monitor_outcome(outcome, terminate_flag.load(Ordering::Relaxed))?;

    match outcome {
        Ok(Some(process_id)) => {
            tracing::info!(%process_id, "deploy monitoring completed");
            Ok(())
        }
        Ok(None) => {
            tracing::info!("deploy monitoring cancelled");
            Ok(())
        }
        Err(err) => anyhow::bail!("deploy failed during monitoring: {err:?}"),
    }
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let (session, profile) = common::create_vmi_session_with_profile()?;

    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    match cli.command {
        Command::Deploy(arguments) => run_deploy(&session, &profile, terminate_flag, arguments),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::common::encode_parameters;

    #[test]
    fn deploy_command_uses_defaults() {
        let cli = Cli::try_parse_from(["windows-bridge", "deploy"]).unwrap();
        let Command::Deploy(arguments) = cli.command;

        assert_eq!(arguments.process, "explorer.exe");
        assert_eq!(arguments.max_download_retries, 0);
        assert_eq!(arguments.output_directory, PathBuf::from("artifacts"));
        assert_eq!(arguments.url, None);
        assert_eq!(arguments.download_path, None);
        assert_eq!(arguments.extraction_directory, None);
        assert_eq!(arguments.execute, None);
        assert_eq!(arguments.arguments, None);
        assert_eq!(arguments.working_directory, None);
        assert_eq!(arguments.show_window, None);
    }

    #[test]
    fn deploy_command_accepts_monitor_with_execute() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--execute",
            r"C:\samples\sample.exe",
            "--monitor",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        assert!(arguments.monitor);
    }

    #[test]
    fn monitor_command_parks_the_execute_gate() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--execute",
            r"C:\samples\sample.exe",
            "--monitor",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(
            request.policy,
            DeployPolicy::default().execute_response(ExecuteResponse::Wait)
        );
    }

    #[test]
    fn monitor_request_carries_executable_basename() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--execute",
            r"C:\samples\sample.exe",
            "--monitor",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(request.monitor.unwrap().executable_name, "sample.exe");
    }

    #[test]
    fn monitor_request_rejects_missing_basename() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--execute",
            r"C:\samples\",
            "--monitor",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let error = arguments.into_request().unwrap_err();

        assert!(error.to_string().contains("no basename"));
    }
    #[test]
    fn windows_executable_basename_handles_both_separators() {
        assert_eq!(
            windows_executable_basename(r"C:\samples\sample.exe"),
            Some("sample.exe")
        );
        assert_eq!(
            windows_executable_basename("C:/samples/sample.exe"),
            Some("sample.exe")
        );
    }

    #[test]
    fn windows_executable_basename_rejects_missing_final_component() {
        for path in ["", "C:\\samples\\", "C:/samples/"] {
            assert_eq!(windows_executable_basename(path), None);
        }
    }

    #[test]
    fn deploy_command_builds_no_operation_request() {
        let cli = Cli::try_parse_from(["windows-bridge", "deploy"]).unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(encode_parameters(&request.parameters), [0, 0, 0, 0]);
        assert_eq!(request.policy, DeployPolicy::default());
    }

    #[test]
    fn deploy_command_maps_download_only_request() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--url",
            "u",
            "--download-path",
            "d",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x04, 0x00, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
            ]
        );
        assert_eq!(request.policy, DeployPolicy::default());
    }

    #[test]
    fn deploy_command_maps_execute_only_request() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--execute",
            "e",
            "--arguments",
            "a",
            "--working-directory",
            "w",
            "--show-window",
            "5",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x02, 0x07, 0x00, 0x00, // flags
                b'e', 0, 0, 0, // executable path
                b'a', 0, 0, 0, // arguments
                b'w', 0, 0, 0, // working directory
                5, 0, 0, 0, // show window
            ]
        );
        assert_eq!(request.policy, DeployPolicy::default().allow_execute());
    }

    #[test]
    fn deploy_command_rejects_incomplete_operations() {
        let incomplete = [
            &["windows-bridge", "deploy", "--url", "u"][..],
            &["windows-bridge", "deploy", "--download-path", "d"][..],
            &["windows-bridge", "deploy", "--extract-to", "x"][..],
            &["windows-bridge", "deploy", "--arguments", "a"][..],
            &["windows-bridge", "deploy", "--working-directory", "w"][..],
            &["windows-bridge", "deploy", "--show-window", "1"][..],
            &["windows-bridge", "deploy", "--monitor"][..],
        ];

        for arguments in incomplete {
            assert!(Cli::try_parse_from(arguments.iter().copied()).is_err());
        }
    }

    #[test]
    fn deploy_command_maps_combined_request() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "deploy",
            "--process",
            "notepad.exe",
            "--url",
            "u",
            "--download-path",
            "d",
            "--extract-to",
            "x",
            "--execute",
            "e",
            "--arguments",
            "a",
            "--working-directory",
            "w",
            "--show-window",
            "5",
            "--max-download-retries",
            "3",
        ])
        .unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request().unwrap();

        assert_eq!(request.process, "notepad.exe");
        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x07, 0x07, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
                b'x', 0, 0, 0, // extraction directory
                b'e', 0, 0, 0, // executable path
                b'a', 0, 0, 0, // arguments
                b'w', 0, 0, 0, // working directory
                5, 0, 0, 0, // show window
            ]
        );
        assert_eq!(
            request.policy,
            DeployPolicy::default()
                .max_download_retries(3)
                .allow_execute()
        );
    }

    #[test]
    fn deploy_status_distinguishes_success_from_failure() {
        assert!(validate_deploy_status(0x0000_0005).is_ok());

        let error = validate_deploy_status(0x0001_fe03).unwrap_err();
        assert!(error.to_string().contains("OperationFailed"));
    }

    #[test]
    fn monitor_requires_execute_waiting_status() {
        assert!(validate_deploy_waiting_status(0x0000_0105).is_ok());
        assert!(validate_deploy_waiting_status(0x0000_0104).is_err());
        assert!(validate_deploy_waiting_status(0x0000_0005).is_err());
        assert!(validate_deploy_waiting_status(0x0001_0105).is_err());
    }

    #[test]
    fn monitor_termination_without_handler_output_is_graceful() {
        let outcome = resolve_monitor_outcome(None, true).unwrap();

        assert_eq!(outcome, Ok(None));
    }
}
