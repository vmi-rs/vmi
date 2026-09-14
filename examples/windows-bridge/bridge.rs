use crate::deploy::DeployStatus;

/// Deployment progress reported to the host event handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::enum_variant_names, reason = "prefix identifies the shellcode")]
pub enum BridgeOutput {
    /// The `deploy` shellcode is waiting to be executed.
    DeployWaiting,

    /// The `deploy` shellcode is allowed to execute under monitoring.
    DeployExecuting,

    /// The `deploy` shellcode has completed with the reported status.
    DeployFinished(DeployStatus),
}
