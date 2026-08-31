//! CLI that drives the msgbox and deploy shellcode recipes into a Windows guest over VMI.

mod bridge;
mod deploy;
mod file_transfer;
mod monitor;
mod msgbox;
mod recipe;

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context as _, Error};
use clap::{Args, Parser, Subcommand};
use isr::{Profile, cache::IsrCache};
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{ProcessId, VmiOsProcess as _, windows::WindowsOs},
    utils::injector::{InjectorHandler, UserMode},
};

use crate::{
    bridge::TerminalStatus,
    deploy::{
        DeployBridge, DeployParameters, DeployPolicy, DeployStage, DeployStatus, ExecuteResponse,
        deploy_recipe,
    },
    monitor::{Monitor, MonitorOutput},
    msgbox::{MsgboxBridge, MsgboxParameters, msgbox_recipe},
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
    /// Displays a message box in a Windows process.
    Msgbox(MsgboxArguments),

    /// Downloads, extracts, or executes content in a Windows process.
    Deploy(DeployArguments),
}

/// Command-line arguments for the msgbox subcommand.
#[derive(Debug, Args)]
struct MsgboxArguments {
    /// Name of the process that will display the message box.
    #[arg(long, default_value = "explorer.exe")]
    process: String,

    /// Message box title.
    #[arg(long, default_value = "Hello from VMI")]
    title: String,

    /// Message box text.
    #[arg(long, default_value = "Injected by windows-bridge")]
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

/// Validates the result returned by `MessageBoxA`.
fn validate_msgbox_result(result: u64) -> Result<u64, Error> {
    anyhow::ensure!(result != 0, "MessageBoxA failed");
    Ok(result)
}

/// Decodes and validates a terminal deploy status.
fn validate_deploy_result(result: u64) -> Result<DeployStatus, Error> {
    let status = DeployStatus::decode(result);
    anyhow::ensure!(
        status.status() == TerminalStatus::SUCCESS,
        "deploy failed: {status:?}"
    );
    Ok(status)
}

/// Validates the injector handoff used before deploy monitoring begins.
fn validate_deploy_waiting_result(result: u64) -> Result<DeployStatus, Error> {
    let status = DeployStatus::decode(result);
    anyhow::ensure!(
        status.stage() == DeployStage::EXECUTE
            && status.status() == TerminalStatus::WAITING
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

/// VMI session type used throughout this example, bound to the Xen driver.
type WindowsVmiSession<'a> = VmiSession<'a, WindowsOs<VmiXenDriver<Amd64>>>;

/// Finds the configured target process while the guest is paused.
fn find_process_id(
    session: &WindowsVmiSession<'_>,
    process_name: &str,
) -> Result<ProcessId, Error> {
    let paused = session.pause_guard()?;
    let vmi = paused.state();
    let process = vmi
        .os()
        .find_process(process_name)?
        .with_context(|| format!("process `{process_name}` not found"))?;
    let process_id = process.id()?;

    tracing::info!(
        process = %process_name,
        pid = %process_id,
        "found target process"
    );

    Ok(process_id)
}

/// Runs a message box injection.
fn run_msgbox(session: &WindowsVmiSession<'_>, arguments: MsgboxArguments) -> Result<(), Error> {
    let MsgboxRequest {
        process,
        parameters,
    } = arguments.into_request();
    let process_id = find_process_id(session, &process)?;
    let result = session
        .handle(|session| {
            InjectorHandler::<_, UserMode, _, MsgboxBridge>::with_bridge(
                session,
                MsgboxBridge,
                msgbox_recipe(&parameters),
            )?
            .with_pid(process_id)
        })?
        .context("msgbox injection interrupted")?
        .map_err(|packet| anyhow::anyhow!("unhandled msgbox bridge packet: {packet:?}"))?;
    let result = validate_msgbox_result(result)?;

    tracing::info!(result, "message box closed");
    Ok(())
}

/// Runs a deploy injection.
fn run_deploy(
    session: &WindowsVmiSession<'_>,
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
    let process_id = find_process_id(session, &process)?;
    let result = session
        .handle(|session| {
            InjectorHandler::<_, UserMode, _, DeployBridge>::with_bridge(
                session,
                DeployBridge::new(policy),
                deploy_recipe(&parameters),
            )?
            .with_pid(process_id)
        })?
        .context("deploy injection interrupted")?
        .map_err(|packet| anyhow::anyhow!("unhandled deploy bridge packet: {packet:?}"))?;

    let monitor = match monitor {
        Some(monitor) => monitor,
        None => {
            let status = validate_deploy_result(result)?;
            tracing::info!(?status, "deploy completed");
            return Ok(());
        }
    };

    let status = validate_deploy_waiting_result(result)?;
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

    let filter = EnvFilter::default()
        .add_directive(tracing::Level::TRACE.into())
        .add_directive("reqwest=warn".parse()?)
        .add_directive("rustls=warn".parse()?);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Setup VMI.
    let driver = VmiXenDriver::<Amd64>::try_from_env()?
        .context("invalid VMI_XEN_DOMAIN environment variable")?;
    let core = VmiCore::new(driver)?;

    // Try to find the kernel information.
    // This is necessary in order to load the profile.
    let kernel_info = {
        let _pause_guard = core.pause_guard()?;
        let registers = core.registers(VcpuId(0))?;

        WindowsOs::find_kernel(&core, &registers)?.context("cannot find kernel information")?
    };

    // Load the kernel profile.
    // The profile contains offsets to kernel functions and data structures.
    tracing::info!(codeview = ?kernel_info.codeview, "loading kernel profile");
    let isr = IsrCache::new("cache")?;
    let entry = isr.entry_from_codeview(kernel_info.codeview)?;
    let profile = entry.profile()?;

    // Create the VMI session.
    tracing::info!("creating VMI session");
    let terminate_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGALRM, terminate_flag.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate_flag.clone())?;

    let os = WindowsOs::<VmiXenDriver<Amd64>>::new(&profile)?;
    let session = VmiSession::new(&core, &os);

    match cli.command {
        Command::Msgbox(arguments) => run_msgbox(&session, arguments),
        Command::Deploy(arguments) => run_deploy(&session, &profile, terminate_flag, arguments),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::recipe::encode_parameters;

    #[test]
    fn msgbox_command_uses_defaults() {
        let cli = Cli::try_parse_from(["windows-bridge", "msgbox"]).unwrap();
        let Command::Msgbox(arguments) = cli.command
        else {
            panic!("expected msgbox command");
        };

        assert_eq!(arguments.process, "explorer.exe");
        assert_eq!(arguments.title, "Hello from VMI");
        assert_eq!(arguments.text, "Injected by windows-bridge");
    }

    #[test]
    fn deploy_command_uses_defaults() {
        let cli = Cli::try_parse_from(["windows-bridge", "deploy"]).unwrap();
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
        let Command::Deploy(arguments) = cli.command
        else {
            panic!("expected deploy command");
        };

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
    fn deploy_result_distinguishes_success_from_failure() {
        assert!(validate_deploy_result(0x0000_0005).is_ok());

        let error = validate_deploy_result(0x0001_fe03).unwrap_err();
        assert!(error.to_string().contains("OperationFailed"));
    }

    #[test]
    fn monitor_requires_execute_waiting_result() {
        assert!(validate_deploy_waiting_result(0x0000_0105).is_ok());
        assert!(validate_deploy_waiting_result(0x0000_0104).is_err());
        assert!(validate_deploy_waiting_result(0x0000_0005).is_err());
        assert!(validate_deploy_waiting_result(0x0001_0105).is_err());
    }

    #[test]
    fn monitor_termination_without_handler_output_is_graceful() {
        let outcome = resolve_monitor_outcome(None, true).unwrap();

        assert_eq!(outcome, Ok(None));
    }

    #[test]
    fn msgbox_command_accepts_overrides() {
        let cli = Cli::try_parse_from([
            "windows-bridge",
            "msgbox",
            "--process",
            "notepad.exe",
            "--title",
            "Custom title",
            "--text",
            "Custom text",
        ])
        .unwrap();
        let Command::Msgbox(arguments) = cli.command
        else {
            panic!("expected msgbox command");
        };

        let MsgboxRequest {
            process,
            parameters,
        } = arguments.into_request();

        assert_eq!(process, "notepad.exe");
        assert_eq!(
            encode_parameters(&parameters),
            b"Custom title\0Custom text\0"
        );
    }

    #[test]
    fn zero_message_box_result_is_an_error() {
        let error = validate_msgbox_result(0).unwrap_err();

        assert_eq!(error.to_string(), "MessageBoxA failed");
    }
}
