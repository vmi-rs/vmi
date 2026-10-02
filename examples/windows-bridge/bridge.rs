use crate::deploy::DeployStatus;

/// Deployment progress reported to the host event handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "shared bridge results identify the reporting payload"
)]
pub enum BridgeResult {
    /// The deploy payload is waiting to be executed.
    DeployWaiting,

    /// The deploy payload is allowed to execute under monitoring.
    DeployExecuting,

    /// The deploy payload has completed with the reported status.
    DeployFinished(DeployStatus),
}
