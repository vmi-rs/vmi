use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        injector::InjectorStatusCode,
    },
};

use crate::bridge::{
    METHOD_EXIT, RESPONSE_ABORT, RESPONSE_CONTINUE, RESPONSE_WAIT, TerminalResult, TerminalStatus,
    impl_bridge_contract, impl_bridge_stage,
};

/// Deploy operation stage encoded in a packed result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeployStage(u8);

impl_bridge_stage!(DeployStage);

impl DeployStage {
    /// No operation ran.
    pub const NONE: Self = Self(0x00);

    /// Parameter parsing failed.
    pub const PARAMETERS: Self = Self(0x01);

    /// Initialization failed.
    pub const INITIALIZATION: Self = Self(0x02);

    /// Download completed or failed.
    pub const DOWNLOAD: Self = Self(0x03);

    /// Extraction completed or failed.
    pub const EXTRACT: Self = Self(0x04);

    /// Execution completed or failed.
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

/// Decoded status returned by the injector handler.
pub type DeployStatus = TerminalResult<DeployStage>;

/// Host response when the shellcode reaches the execution gate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteResponse {
    /// Allows the shellcode to execute the configured program.
    Continue,

    /// Aborts the shellcode before process execution.
    #[default]
    Abort,

    /// Parks the shellcode immediately before process execution.
    Wait,
}

/// Host-side limits and permissions for a deploy request.
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

/// Handles download and execute gates plus the terminal shellcode result.
#[derive(Debug)]
pub struct DeployBridge {
    /// Policy applied to shellcode requests.
    policy: DeployPolicy,
}

impl_bridge_contract!(DeployBridge);

impl DeployBridge {
    /// Deploy bridge request identifier.
    pub(crate) const REQUEST: u16 = 0x0001;

    /// Download readiness and retry method.
    const METHOD_DOWNLOAD: u16 = 0x0001;

    /// Execution policy gate method.
    pub(crate) const METHOD_EXECUTE: u16 = 0x0002;

    /// Terminal result method.
    const METHOD_EXIT: u16 = METHOD_EXIT;

    /// Creates a deploy bridge with the supplied host policy.
    pub fn new(policy: DeployPolicy) -> Self {
        Self { policy }
    }

    /// Produces the protocol response for one deploy packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        match packet.method() {
            Self::METHOD_DOWNLOAD => self.handle_download(packet),
            Self::METHOD_EXECUTE => self.handle_execute(packet),
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Applies the download retry limit to a readiness or failure report.
    fn handle_download(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let attempt = packet.value1();
        let native_code = packet.value2();

        let response = if attempt == 0 || attempt <= self.policy.max_download_retries {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        };

        tracing::debug!(attempt, native_code, response, "deploy download gate");

        Some(BridgeResponse::new(response))
    }

    /// Applies the configured response to an execution gate.
    fn handle_execute(&self, _packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let response = match self.policy.execute_response {
            ExecuteResponse::Continue => BridgeResponse::new(RESPONSE_CONTINUE),
            ExecuteResponse::Abort => BridgeResponse::new(RESPONSE_ABORT),
            ExecuteResponse::Wait => BridgeResponse::new(RESPONSE_WAIT).with_result(
                DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::WAITING).encode(),
            ),
        };

        tracing::debug!(
            response = ?self.policy.execute_response,
            "deploy execute gate"
        );

        Some(response)
    }

    /// Completes the injector from a terminal result packet.
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let result = DeployStatus::decode(packet.value1());
        let native_code = packet.value2();

        tracing::debug!(
            stage = ?result.stage(),
            status = ?result.status(),
            code = result.code(),
            native_code,
            "deploy shellcode completed"
        );

        Some(BridgeResponse::default().with_result(packet.value1()))
    }

    /// Logs and rejects one packet with an unknown deploy bridge method.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        tracing::error!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown deploy bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, InjectorStatusCode> for DeployBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    /// Deploy bridge request identifier.
    const REQUEST: u16 = DeployBridge::REQUEST;

    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>, InjectorStatusCode>>::REQUEST
        );

        self.handle_packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use vmi::utils::bridge::BridgeContract;

    use super::*;
    use crate::bridge::BRIDGE_MAGIC;

    /// Creates a packet routed to the deploy handler.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, 0x0001, method)
    }

    #[test]
    fn contract_matches_guest_constants() {
        assert_eq!(<DeployBridge as BridgeContract>::MAGIC, Some(0x4249_4d56));
        assert_eq!(
            <DeployBridge as BridgeContract>::VERIFY_VALUE3,
            Some(0x2133_5352_2d49_4d56)
        );
        assert_eq!(
            <DeployBridge as BridgeContract>::VERIFY_VALUE4,
            Some(0x2134_5352_2d49_4d56)
        );
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
            assert_eq!(response.value1(), Some(RESPONSE_CONTINUE));
        }

        let response = bridge
            .handle_packet(packet(DeployBridge::METHOD_DOWNLOAD).with_value1(3))
            .expect("valid download packet");
        assert_eq!(response.value1(), Some(RESPONSE_ABORT));
    }

    #[test]
    fn execute_gate_applies_configured_response() {
        for (policy_response, wire_response, handler_result) in [
            (ExecuteResponse::Continue, RESPONSE_CONTINUE, None),
            (ExecuteResponse::Abort, RESPONSE_ABORT, None),
            (ExecuteResponse::Wait, RESPONSE_WAIT, Some(0x0000_0105)),
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
    fn execute_permission_helpers_map_to_response() {
        for (policy, expected) in [
            (DeployPolicy::default().allow_execute(), RESPONSE_CONTINUE),
            (
                DeployPolicy::default().maybe_allow_execute(true),
                RESPONSE_CONTINUE,
            ),
            (
                DeployPolicy::default().maybe_allow_execute(false),
                RESPONSE_ABORT,
            ),
        ] {
            let response = DeployBridge::new(policy)
                .handle_packet(packet(DeployBridge::METHOD_EXECUTE))
                .expect("valid execute packet");
            assert_eq!(response.value1(), Some(expected));
        }
    }

    #[test]
    fn status_api_keeps_const_construction_and_accessors() {
        const STATUS: DeployStatus =
            DeployStatus::new(DeployStage::EXECUTE, TerminalStatus::WAITING);
        const STAGE: DeployStage = STATUS.stage();
        const TERMINAL_STATUS: TerminalStatus = STATUS.status();
        const CODE: u8 = STATUS.code();

        let packed = STATUS.encode();
        let decoded = DeployStatus::decode(packed);

        assert_eq!(packed, 0x0000_0105);
        assert_eq!(decoded, STATUS);
        assert_eq!(STAGE, DeployStage::EXECUTE);
        assert_eq!(TERMINAL_STATUS, TerminalStatus::WAITING);
        assert_eq!(CODE, 0);
    }

    #[test]
    fn exit_completes_with_packed_status() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0x0002_fe03;
        let response = bridge
            .handle_packet(
                packet(METHOD_EXIT)
                    .with_value1(packed)
                    .with_value2(0x8000_4005),
            )
            .expect("valid exit packet");

        assert_eq!(response.into_result(), Some(packed));
        let result = DeployStatus::decode(packed);
        assert_eq!(result.stage(), DeployStage::DOWNLOAD);
        assert_eq!(result.status(), TerminalStatus::OPERATION_FAILED);
        assert_eq!(result.code(), 2);
    }
    #[test]
    fn corrupt_terminal_values_are_preserved() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0xab5d_7ce6;

        let result = DeployStatus::decode(packed);
        assert_eq!(result.stage(), DeployStage(0xe6));
        assert_eq!(result.status(), TerminalStatus(0x7c));
        assert_eq!(result.code(), 0x5d);
        assert_eq!(format!("{:?}", result.stage()), "230");
        assert_eq!(format!("{:?}", result.status()), "124");

        let response = bridge
            .handle_packet(packet(METHOD_EXIT).with_value1(packed))
            .expect("corrupt terminal values must produce a response");
        assert_eq!(response.into_result(), Some(packed));
    }
}
