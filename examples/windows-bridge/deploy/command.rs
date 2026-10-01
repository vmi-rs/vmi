use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context as _, Error};
use clap::Args;
use isr::Profile;
use vmi::{
    VmiSession,
    arch::amd64::Amd64,
    driver::VmiFullDriver,
    os::windows::WindowsOs,
    utils::{injector::UserInjectorHandler, shellcode::StatusKind},
};

use super::{
    bridge::{DeployBridge, DeployPolicy, DeployStatus, ExecuteResponse},
    parameters::DeployParameters,
    recipe::deploy_recipe,
};
use crate::{bridge::BridgeOutput, common, monitor::Monitor};

/// Arguments for the `deploy` command.
#[derive(Debug, Args)]
pub struct DeployArguments {
    /// Process in which the `deploy` shellcode runs.
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

/// Resolved monitor settings for a `deploy` request.
#[derive(Debug)]
struct DeployMonitorRequest {
    /// Host directory receiving transferred files.
    output_directory: PathBuf,
}

/// Resolved `deploy` request.
#[derive(Debug)]
struct DeployRequest {
    /// Process in which the `deploy` shellcode runs.
    process: String,

    /// Parameters for the `deploy` shellcode.
    parameters: DeployParameters,

    /// Policy applied to the `deploy` bridge.
    policy: DeployPolicy,

    /// Monitor settings used after injection.
    monitor: Option<DeployMonitorRequest>,
}

impl DeployArguments {
    /// Converts the command-line arguments into a `deploy` request.
    fn into_request(self) -> DeployRequest {
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
            Some(DeployMonitorRequest { output_directory })
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
                    download_path.expect("--download-path required by clap when --url is set");

                DeployParameters::builder()
                    .download(url)
                    .download_path(download_path)
                    .maybe_extraction_directory(extraction_directory)
                    .build()
            }
            (Some(url), Some(executable)) => {
                let download_path =
                    download_path.expect("--download-path required by clap when --url is set");

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

        DeployRequest {
            process,
            parameters,
            policy,
            monitor: monitor_request,
        }
    }
}

/// Validates a successful final deploy output.
fn validate_deploy_output(output: BridgeOutput) -> Result<DeployStatus, Error> {
    let status = match output {
        BridgeOutput::DeployFinished(status) => status,
        BridgeOutput::DeployWaiting | BridgeOutput::DeployExecuting => {
            anyhow::bail!("unexpected deploy output: {output:?}")
        }
    };

    anyhow::ensure!(
        status.kind() == StatusKind::SUCCESS,
        "deploy failed: {status:?}"
    );

    Ok(status)
}

/// Validates the injector output used before deploy monitoring begins.
fn validate_deploy_waiting_output(output: BridgeOutput) -> Result<(), Error> {
    anyhow::ensure!(
        output == BridgeOutput::DeployWaiting,
        "deploy waiting failed: {output:?}"
    );

    Ok(())
}

/// Runs a `deploy` injection.
pub fn run<Driver>(
    session: &VmiSession<'_, WindowsOs<Driver>>,
    profile: &Profile,
    terminate_flag: Arc<AtomicBool>,
    arguments: DeployArguments,
) -> Result<(), Error>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    let DeployRequest {
        process,
        parameters,
        policy,
        monitor,
    } = arguments.into_request();

    let process_id = common::find_process_id(session, &process)?;

    let output = session
        .handle(|session| {
            UserInjectorHandler::new(session, deploy_recipe(&parameters))?
                .with_bridge(DeployBridge::new(policy))?
                .with_pid(process_id)
        })?
        .context("deploy injection interrupted")?
        .context("deploy bridge completed without an output")?
        .map_err(|packet| anyhow::anyhow!("unhandled deploy bridge packet: {packet:?}"))?;

    let monitor = match monitor {
        Some(monitor) => monitor,
        None => {
            // Without --monitor, there is nothing else to set up.
            // The requested work should be finished, so check that it succeeded.
            let status = validate_deploy_output(output)?;
            tracing::info!(?status, "deploy completed");
            return Ok(());
        }
    };

    // With --monitor, we told the code running in the VM to wait before
    // starting the program. This gives us time to set up the monitor.
    // Otherwise, the program could start before we are ready to watch it.
    //
    // Check that it is still waiting. The monitor will then allow it to start.
    validate_deploy_waiting_output(output)?;
    tracing::info!("deploy injector parked at execute gate");

    let monitor_terminate_flag = terminate_flag.clone();
    let output = session.handle(|session| {
        Monitor::new(
            session,
            profile,
            monitor_terminate_flag,
            monitor.output_directory,
        )
    })?;

    match output {
        Some(Ok(Some(pid))) => tracing::info!(%pid, "deploy monitoring completed"),
        Some(Ok(None)) => tracing::info!("deploy monitoring cancelled"),
        Some(Err(err)) => anyhow::bail!("deploy failed during monitoring: {err:?}"),
        None if terminate_flag.load(Ordering::Relaxed) => {
            tracing::info!("deploy monitoring cancelled")
        }
        None => anyhow::bail!("deploy monitoring interrupted"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{super::parameters::encode_parameters, *};
    use crate::{Cli, Command};

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
    fn deploy_command_builds_no_operation_request() {
        let cli = Cli::try_parse_from(["windows-bridge", "deploy"]).unwrap();
        let Command::Deploy(arguments) = cli.command;

        let request = arguments.into_request();

        assert_eq!(encode_parameters(&request.parameters), [0, 0, 0, 0]);
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

        let request = arguments.into_request();

        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x01, 0x00, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
            ]
        );
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

        let request = arguments.into_request();

        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x02, 0x70, 0x00, 0x00, // flags
                b'e', 0, 0, 0, // executable path
                b'a', 0, 0, 0, // arguments
                b'w', 0, 0, 0, // working directory
                5, 0, 0, 0, // show window
            ]
        );
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

        let request = arguments.into_request();

        assert_eq!(request.process, "notepad.exe");
        assert_eq!(
            encode_parameters(&request.parameters),
            [
                0x03, 0x71, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
                b'x', 0, 0, 0, // extraction directory
                b'e', 0, 0, 0, // executable path
                b'a', 0, 0, 0, // arguments
                b'w', 0, 0, 0, // working directory
                5, 0, 0, 0, // show window
            ]
        );
    }

    #[test]
    fn deploy_output_requires_successful_completion() {
        let status = DeployStatus::decode(0x0000_0005);
        assert_eq!(
            validate_deploy_output(BridgeOutput::DeployFinished(status)).unwrap(),
            status
        );

        for output in [
            BridgeOutput::DeployFinished(DeployStatus::decode(0x0001_fe03)),
            BridgeOutput::DeployWaiting,
            BridgeOutput::DeployExecuting,
        ] {
            assert!(validate_deploy_output(output).is_err());
        }
    }

    #[test]
    fn monitor_requires_waiting_handoff() {
        assert!(validate_deploy_waiting_output(BridgeOutput::DeployWaiting).is_ok());
        assert!(validate_deploy_waiting_output(BridgeOutput::DeployExecuting).is_err());
        assert!(
            validate_deploy_waiting_output(BridgeOutput::DeployFinished(DeployStatus::decode(
                0x0000_0005
            )))
            .is_err()
        );
        assert!(
            validate_deploy_waiting_output(BridgeOutput::DeployFinished(DeployStatus::decode(
                0x0001_fe03
            )))
            .is_err()
        );
    }
}
