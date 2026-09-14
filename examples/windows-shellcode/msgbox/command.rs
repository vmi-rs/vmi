use anyhow::{Context as _, Error};
use clap::Args;
use vmi::{
    VmiSession, arch::amd64::Amd64, driver::VmiFullDriver, os::windows::WindowsOs,
    utils::injector::UserInjectorHandler,
};

use super::{
    bridge::MsgboxBridge,
    parameters::MsgboxParameters,
    recipe::{msgbox_call_recipe, msgbox_spawn_recipe},
};
use crate::{Execution, common};

/// Arguments shared by the `msgbox` commands.
#[derive(Debug, Args)]
pub struct MsgboxArguments {
    /// Process in which the message box is displayed.
    #[arg(long, default_value = "explorer.exe")]
    process: String,

    /// Message box title.
    #[arg(long, default_value = "Hello from VMI")]
    title: String,

    /// Message box text.
    #[arg(long, default_value = "Injected by windows-shellcode")]
    text: String,
}

/// Resolved `msgbox` request.
#[derive(Debug)]
struct MsgboxRequest {
    /// Process in which the `msgbox` shellcode runs.
    process: String,

    /// Parameters for the `msgbox` shellcode.
    parameters: MsgboxParameters,
}

impl MsgboxArguments {
    /// Converts the command-line arguments into a `msgbox` request.
    fn into_request(self) -> MsgboxRequest {
        MsgboxRequest {
            process: self.process,
            parameters: MsgboxParameters::new(self.title, self.text),
        }
    }
}

/// Validates the result returned by `MessageBoxA`.
fn validate_result(result: u64) -> Result<u64, Error> {
    anyhow::ensure!(result != 0, "MessageBoxA failed");

    Ok(result)
}

/// Runs a `msgbox` injection.
pub fn run<Driver>(
    session: &VmiSession<'_, WindowsOs<Driver>>,
    arguments: MsgboxArguments,
    execution: Execution,
) -> Result<(), Error>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
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

    let result = validate_result(result)?;

    tracing::info!(result, "message box closed");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_message_box_result_is_an_error() {
        assert!(validate_result(0).is_err());
        assert_eq!(validate_result(1).unwrap(), 1);
    }
}
