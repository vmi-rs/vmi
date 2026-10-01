use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        shellcode::{Status, impl_bridge_contract, impl_bridge_stage},
    },
};

use crate::bridge::BridgeResult;

/// Stage reported by the `deploy` shellcode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeployStage(u8);

impl_bridge_stage!(DeployStage);

impl DeployStage {
    /// No deploy operation was started.
    pub const NONE: Self = Self(0x00);

    /// Parameter parsing stage.
    pub const PARAMETERS: Self = Self(0x01);

    /// Initialization stage.
    pub const INITIALIZATION: Self = Self(0x02);

    /// Download stage.
    pub const DOWNLOAD: Self = Self(0x03);

    /// Extraction stage.
    pub const EXTRACT: Self = Self(0x04);

    /// Execution stage.
    pub const EXECUTE: Self = Self(0x05);
}

impl std::fmt::Debug for DeployStage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::NONE => "None",
            Self::PARAMETERS => "Parameters",
            Self::INITIALIZATION => "Initialization",
            Self::DOWNLOAD => "Download",
            Self::EXTRACT => "Extract",
            Self::EXECUTE => "Execute",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Status reported by the `deploy` shellcode.
pub type DeployStatus = Status<DeployStage>;

/// Host response when the shellcode reaches the execution gate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteResponse {
    /// Allows the shellcode to execute the configured program.
    Continue,

    /// Allows execution and notifies the monitor before the guest resumes.
    ContinueAndNotify,

    /// Aborts the shellcode before process execution.
    #[default]
    Abort,

    /// Parks the shellcode immediately before process execution.
    Wait,
}

/// Policy applied to a `deploy` request.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeployPolicy {
    /// Number of retries allowed after failed download attempts.
    max_download_retries: u64,

    /// Response returned when the shellcode reaches the execution gate.
    execute_response: ExecuteResponse,
}

impl DeployPolicy {
    /// Sets the number of retries allowed after failed download attempts.
    pub fn max_download_retries(self, max_download_retries: u64) -> Self {
        Self {
            max_download_retries,
            ..self
        }
    }

    /// Sets the response returned at the execution gate.
    pub fn execute_response(self, execute_response: ExecuteResponse) -> Self {
        Self {
            execute_response,
            ..self
        }
    }

    /// Allows process execution.
    #[expect(dead_code, reason = "retained as a convenience")]
    pub fn allow_execute(self) -> Self {
        self.execute_response(ExecuteResponse::Continue)
    }

    /// Allows process execution when `allow_execute` is true.
    pub fn maybe_allow_execute(self, allow_execute: bool) -> Self {
        self.execute_response(if allow_execute {
            ExecuteResponse::Continue
        }
        else {
            ExecuteResponse::Abort
        })
    }
}

/// Handles communication with the `deploy` shellcode.
#[derive(Debug)]
pub struct DeployBridge {
    /// Policy applied to shellcode requests.
    policy: DeployPolicy,
}

impl_bridge_contract!(DeployBridge);

impl DeployBridge {
    /// Method used to report download readiness or failure.
    const METHOD_DOWNLOAD: u16 = 0x0001;

    /// Method used to request permission to execute.
    const METHOD_EXECUTE: u16 = 0x0002;

    /// Method used to report the final status.
    const METHOD_EXIT: u16 = 0xffff;

    /// Allows the shellcode to continue its current stage.
    const RESPONSE_CONTINUE: u64 = 0x0000_0000;

    /// Leaves the shellcode waiting at its current stage.
    const RESPONSE_WAIT: u64 = 0x0000_0001;

    /// Aborts the shellcode's current stage.
    const RESPONSE_ABORT: u64 = 0xffff_ffff;

    /// Creates a `deploy` bridge with the given policy.
    pub fn new(policy: DeployPolicy) -> Self {
        Self { policy }
    }

    /// Handles a `deploy` bridge packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeResult>> {
        match packet.method() {
            Self::METHOD_DOWNLOAD => self.handle_download(packet),
            Self::METHOD_EXECUTE => self.handle_execute(packet),
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Handles the [`METHOD_DOWNLOAD`] bridge method.
    ///
    /// Applies the download retry limit to a readiness or failure report.
    ///
    /// [`METHOD_DOWNLOAD`]: Self::METHOD_DOWNLOAD
    fn handle_download(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeResult>> {
        let attempt = packet.value1();
        let native_code = packet.value2();

        let response = if attempt == 0 || attempt <= self.policy.max_download_retries {
            Self::RESPONSE_CONTINUE
        }
        else {
            Self::RESPONSE_ABORT
        };

        tracing::debug!(attempt, native_code, response, "download gate");

        Some(BridgeResponse::new(response))
    }

    /// Handles the [`METHOD_EXECUTE`] bridge method.
    ///
    /// Returns the configured execution response.
    ///
    /// [`METHOD_EXECUTE`]: Self::METHOD_EXECUTE
    fn handle_execute(&self, _packet: BridgePacket) -> Option<BridgeResponse<BridgeResult>> {
        let response = match self.policy.execute_response {
            ExecuteResponse::Continue => BridgeResponse::new(Self::RESPONSE_CONTINUE),
            ExecuteResponse::ContinueAndNotify => BridgeResponse::new(Self::RESPONSE_CONTINUE)
                .with_result(BridgeResult::DeployExecuting),
            ExecuteResponse::Abort => BridgeResponse::new(Self::RESPONSE_ABORT),
            ExecuteResponse::Wait => {
                BridgeResponse::new(Self::RESPONSE_WAIT).with_result(BridgeResult::DeployWaiting)
            }
        };

        tracing::debug!(
            response = ?self.policy.execute_response,
            "execute gate"
        );

        Some(response)
    }

    /// Handles the [`METHOD_EXIT`] bridge method.
    ///
    /// [`METHOD_EXIT`]: Self::METHOD_EXIT
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeResult>> {
        let status = DeployStatus::decode(packet.value1());
        let native_code = packet.value2();

        tracing::debug!(
            stage = ?status.stage(),
            kind = ?status.kind(),
            code = status.code(),
            native_code,
            "shellcode completed"
        );

        Some(BridgeResponse::default().with_result(BridgeResult::DeployFinished(status)))
    }

    /// Handles a bridge packet with an unknown method.
    ///
    /// Logs the packet details and returns no response.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeResult>> {
        tracing::warn!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>> for DeployBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    type Output = BridgeResult;

    /// Request code for the `deploy` shellcode.
    const REQUEST: u16 = 0x0011;

    #[tracing::instrument(name = "deploy", skip_all)]
    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeResult>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>>>::REQUEST
        );

        self.handle_packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use vmi::utils::shellcode::{BRIDGE_MAGIC, StatusKind};

    use super::*;

    /// Creates a `deploy` bridge packet.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, 0x0011, method)
    }

    #[test]
    fn unknown_method_is_not_handled() {
        let bridge = DeployBridge::new(DeployPolicy::default());

        assert!(bridge.handle_unknown(packet(0x1234)).is_none());
        assert!(bridge.handle_packet(packet(0x1234)).is_none());
    }

    #[test]
    fn download_gate_enforces_retry_boundary() {
        let bridge = DeployBridge::new(DeployPolicy::default().max_download_retries(2));

        for attempt in [0, 1, 2] {
            let response = bridge
                .handle_packet(packet(DeployBridge::METHOD_DOWNLOAD).with_value1(attempt))
                .expect("valid download packet");
            assert_eq!(response.value1(), Some(DeployBridge::RESPONSE_CONTINUE));
        }

        let response = bridge
            .handle_packet(packet(DeployBridge::METHOD_DOWNLOAD).with_value1(3))
            .expect("valid download packet");
        assert_eq!(response.value1(), Some(DeployBridge::RESPONSE_ABORT));
    }

    #[test]
    fn execute_gate_applies_configured_response() {
        for (policy_response, wire_response, handler_result) in [
            (
                ExecuteResponse::Continue,
                DeployBridge::RESPONSE_CONTINUE,
                None,
            ),
            (
                ExecuteResponse::ContinueAndNotify,
                DeployBridge::RESPONSE_CONTINUE,
                Some(BridgeResult::DeployExecuting),
            ),
            (ExecuteResponse::Abort, DeployBridge::RESPONSE_ABORT, None),
            (
                ExecuteResponse::Wait,
                DeployBridge::RESPONSE_WAIT,
                Some(BridgeResult::DeployWaiting),
            ),
        ] {
            let bridge =
                DeployBridge::new(DeployPolicy::default().execute_response(policy_response));
            let response = bridge
                .handle_packet(packet(DeployBridge::METHOD_EXECUTE))
                .expect("valid execute packet");

            assert_eq!(response.value1(), Some(wire_response));
            assert_eq!(response.into_result(), handler_result);
        }
    }

    #[test]
    fn exit_completes_with_deploy_status() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0x0002_fe03;
        let response = bridge
            .handle_packet(
                packet(DeployBridge::METHOD_EXIT)
                    .with_value1(packed)
                    .with_value2(0x8000_4005),
            )
            .expect("valid exit packet");

        let status = match response.into_result() {
            Some(BridgeResult::DeployFinished(status)) => status,
            result => panic!("unexpected exit result: {result:?}"),
        };
        assert_eq!(status.stage(), DeployStage::DOWNLOAD);
        assert_eq!(status.kind(), StatusKind::OPERATION_FAILED);
        assert_eq!(status.code(), 2);
    }

    #[test]
    fn corrupt_final_status_values_are_preserved() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0xab5d_7ce6;

        let response = bridge
            .handle_packet(packet(DeployBridge::METHOD_EXIT).with_value1(packed))
            .expect("corrupt final status values must produce a response");
        let status = match response.into_result() {
            Some(BridgeResult::DeployFinished(status)) => status,
            result => panic!("unexpected exit result: {result:?}"),
        };
        assert_eq!(status.stage(), DeployStage(0xe6));
        assert_eq!(status.kind(), StatusKind(0x7c));
        assert_eq!(status.code(), 0x5d);
    }
}
