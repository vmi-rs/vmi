use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Error};
use clap::Args;
use vmi::{
    VmiSession,
    arch::amd64::Amd64,
    driver::VmiFullDriver,
    os::windows::WindowsOs,
    utils::{
        injector::KernelInjectorHandler,
        shellcode::{EncodedStatus, StatusKind},
    },
};

use super::{
    bridge::{KernelFileBridge, KernelFileStatus},
    parameters::KernelFileParameters,
    recipe::{kernel_file_call_recipe, kernel_file_spawn_recipe},
};
use crate::Execution;

/// Arguments shared by the `kernel-file` commands.
#[derive(Debug, Args)]
pub struct KernelFileArguments {
    /// Guest path of the file to create.
    ///
    /// Defaults to `C:\Users\John\Desktop\test-{timestamp}.txt`.
    /// Paths beginning with `\` are treated as NT paths and left unchanged.
    #[arg(long)]
    path: Option<String>,
}

impl KernelFileArguments {
    /// Converts the command-line arguments into `kernel-file` parameters.
    fn into_parameters(self) -> KernelFileParameters {
        KernelFileParameters::new(self.path.unwrap_or_else(default_path))
    }
}

/// Returns a default path for the `kernel-file` shellcode.
fn default_path() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);

    format!(r"C:\Users\John\Desktop\test-{timestamp}.txt")
}

/// Decodes and validates a final `kernel-file` status.
fn validate_status(encoded_status: EncodedStatus) -> Result<KernelFileStatus, Error> {
    let status = KernelFileStatus::decode(encoded_status);

    anyhow::ensure!(
        status.kind() == StatusKind::SUCCESS,
        "kernel-file shellcode failed: {status:?}"
    );

    Ok(status)
}

/// Runs a `kernel-file` injection.
pub fn run<Driver>(
    session: &VmiSession<'_, WindowsOs<Driver>>,
    arguments: KernelFileArguments,
    execution: Execution,
) -> Result<(), Error>
where
    Driver: VmiFullDriver<Architecture = Amd64>,
{
    let parameters = arguments.into_parameters();

    tracing::info!(
        path = parameters.nt_path(),
        ?execution,
        "injecting kernel-file shellcode"
    );

    let encoded_status = session
        .handle(|session| {
            let recipe = match execution {
                Execution::Call => kernel_file_call_recipe(&parameters),
                Execution::Spawn => kernel_file_spawn_recipe(&parameters),
            };

            KernelInjectorHandler::new(session, recipe)?.with_bridge(KernelFileBridge)
        })?
        .context("kernel-file injection interrupted")?
        .context("kernel-file bridge completed without an output")?
        .map_err(|packet| anyhow::anyhow!("unhandled kernel-file bridge packet: {packet:?}"))?;

    let status = validate_status(encoded_status)?;

    tracing::info!(?status, path = parameters.nt_path(), "file written");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_file::bridge::KernelFileStage;

    #[test]
    fn kernel_status_distinguishes_success_from_failure() {
        // Stage `Write`, status kind `Success`, no error code.
        assert_eq!(
            validate_status(0x0000_0002).unwrap().stage(),
            KernelFileStage::WRITE
        );

        // Stage `Create`, status kind `OperationFailed`, error `zw_create_file`.
        assert!(validate_status(0x0002_fe01).is_err());
    }
}
