use crate::deploy::DeployStatus;

/// Reports a deployment handoff or completion to the host event handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "shared bridge results identify the reporting payload"
)]
pub enum BridgeResult {
    /// The deploy payload is parked at its execution gate.
    DeployWaiting,

    /// The deploy payload is allowed to execute under monitoring.
    DeployExecuting,

    /// The deploy payload has completed with the reported status.
    DeployFinished(DeployStatus),
}
