mod bridge;
mod msgbox;
mod pull;
mod recipe;

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context as _, Error};
use clap::{Args, Parser, Subcommand};
use isr::cache::IsrCache;
use tracing_subscriber::EnvFilter;
use vmi::{
    VcpuId, VmiCore, VmiSession,
    arch::amd64::Amd64,
    driver::xen::VmiXenDriver,
    os::{VmiOsProcess as _, windows::WindowsOs},
    utils::injector::{InjectorHandler, UserMode},
};

use crate::msgbox::{MsgboxBridge, MsgboxParameters, msgbox_recipe};

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Operation to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Displays a message box in a Windows process.
    Msgbox(MsgboxArguments),
}

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

impl MsgboxArguments {
    /// Converts CLI arguments into a target process and shellcode parameters.
    fn into_request(self) -> (String, MsgboxParameters) {
        (self.process, MsgboxParameters::new(self.title, self.text))
    }
}

/// Validates the result returned by `MessageBoxA`.
fn validate_msgbox_result(result: u64) -> Result<u64, Error> {
    anyhow::ensure!(result != 0, "MessageBoxA failed");
    Ok(result)
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let Command::Msgbox(arguments) = cli.command;
    let (process_name, parameters) = arguments.into_request();

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

    let process_id = {
        let paused = session.pause_guard()?;
        let vmi = paused.state();
        let process = vmi
            .os()
            .find_process(&process_name)?
            .with_context(|| format!("process `{process_name}` not found"))?;
        let process_id = process.id()?;

        tracing::info!(
            process = %process_name,
            pid = %process_id,
            "found target process"
        );

        process_id
    };

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

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn msgbox_command_uses_defaults() {
        let Cli {
            command: Command::Msgbox(arguments),
        } = Cli::try_parse_from(["windows-bridge", "msgbox"]).unwrap();

        assert_eq!(arguments.process, "explorer.exe");
        assert_eq!(arguments.title, "Hello from VMI");
        assert_eq!(arguments.text, "Injected by windows-bridge");
    }

    #[test]
    fn msgbox_command_accepts_overrides() {
        let Cli {
            command: Command::Msgbox(arguments),
        } = Cli::try_parse_from([
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

        let (process, parameters) = arguments.into_request();

        assert_eq!(process, "notepad.exe");
        assert_eq!(parameters.serialize(), b"Custom title\0Custom text\0");
    }

    #[test]
    fn zero_message_box_result_is_an_error() {
        let error = validate_msgbox_result(0).unwrap_err();

        assert_eq!(error.to_string(), "MessageBoxA failed");
    }
}
