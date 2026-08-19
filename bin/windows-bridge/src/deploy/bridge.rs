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
    METHOD_EXIT, RESPONSE_ABORT, RESPONSE_CONTINUE, TerminalStatus, impl_bridge_contract,
};

/// Deploy operation stage encoded in a terminal status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeployStage(u8);

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

/// Decoded status returned by the injector after a terminal bridge packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeployStatus {
    /// Stage that produced the terminal result.
    stage: DeployStage,

    /// Stable terminal status.
    status: TerminalStatus,

    /// Stage-specific compact detail code.
    detail: u8,
}

impl DeployStatus {
    /// Decodes the packed status returned by the injector.
    pub fn decode(value: InjectorStatusCode) -> Self {
        Self {
            stage: DeployStage(value as u8),
            status: TerminalStatus((value >> 16) as u8),
            detail: (value >> 8) as u8,
        }
    }

    /// Returns the stage that produced the result.
    pub fn stage(self) -> DeployStage {
        self.stage
    }

    /// Returns the stable terminal status.
    pub fn status(self) -> TerminalStatus {
        self.status
    }

    /// Returns the stage-specific detail code.
    pub fn detail(self) -> u8 {
        self.detail
    }
}

/// Host-side limits and permissions for a deploy request.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeployPolicy {
    /// Number of retries allowed after failed download attempts.
    max_download_retries: u64,

    /// Whether the host permits archive extraction.
    allow_extract: bool,

    /// Whether the host permits process execution.
    allow_execute: bool,
}

impl DeployPolicy {
    /// Sets the number of retries allowed after failed download attempts.
    pub fn max_download_retries(self, max_download_retries: u64) -> Self {
        Self {
            max_download_retries,
            ..self
        }
    }

    /// Allows archive extraction.
    pub fn allow_extract(self) -> Self {
        self.maybe_allow_extract(true)
    }

    /// Allows archive extraction when `allow_extract` is true.
    pub fn maybe_allow_extract(self, allow_extract: bool) -> Self {
        Self {
            allow_extract,
            ..self
        }
    }

    /// Allows process execution.
    pub fn allow_execute(self) -> Self {
        self.maybe_allow_execute(true)
    }

    /// Allows process execution when `allow_execute` is true.
    pub fn maybe_allow_execute(self, allow_execute: bool) -> Self {
        Self {
            allow_execute,
            ..self
        }
    }
}

/// Handles deploy stage gates and the terminal shellcode result.
#[derive(Debug)]
pub struct DeployBridge {
    /// Policy applied to shellcode requests.
    policy: DeployPolicy,
}

impl_bridge_contract!(DeployBridge);

impl DeployBridge {
    /// Download readiness and retry method.
    const METHOD_DOWNLOAD: u16 = 0x0001;

    /// Extraction policy gate method.
    const METHOD_EXTRACT: u16 = 0x0002;

    /// Execution policy gate method.
    const METHOD_EXECUTE: u16 = 0x0003;

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
            Self::METHOD_EXTRACT => self.handle_extract(packet),
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

    /// Applies the extraction policy to an extraction gate.
    fn handle_extract(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        self.stage_response(packet, self.policy.allow_extract, DeployStage::EXTRACT)
    }

    /// Applies the execution policy to an execution gate.
    fn handle_execute(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        self.stage_response(packet, self.policy.allow_execute, DeployStage::EXECUTE)
    }

    /// Applies an independent host permission to an extraction or execution gate.
    fn stage_response(
        &self,
        _packet: BridgePacket,
        allowed: bool,
        stage: DeployStage,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        let response = if allowed {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        };

        tracing::debug!(?stage, allowed, "deploy stage gate");
        Some(BridgeResponse::new(response))
    }

    /// Completes the injector from a terminal result packet.
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let result = DeployStatus::decode(packet.value1());
        let native_code = packet.value2();

        tracing::debug!(
            stage = ?result.stage(),
            status = ?result.status(),
            detail = result.detail(),
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
    const REQUEST: u16 = 0x0001;

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
    fn stage_gates_apply_permissions_independently() {
        let bridge = DeployBridge::new(DeployPolicy::default().allow_execute());

        let extract = bridge
            .handle_packet(packet(DeployBridge::METHOD_EXTRACT))
            .expect("valid extract packet");
        assert_eq!(extract.value1(), Some(RESPONSE_ABORT));

        let execute = bridge
            .handle_packet(packet(DeployBridge::METHOD_EXECUTE))
            .expect("valid execute packet");
        assert_eq!(execute.value1(), Some(RESPONSE_CONTINUE));
    }

    #[test]
    fn conditional_stage_gates_apply_permissions_independently() {
        let bridge = DeployBridge::new(
            DeployPolicy::default()
                .maybe_allow_extract(true)
                .maybe_allow_execute(false),
        );

        let extract = bridge
            .handle_packet(packet(DeployBridge::METHOD_EXTRACT))
            .expect("valid extract packet");
        assert_eq!(extract.value1(), Some(RESPONSE_CONTINUE));

        let execute = bridge
            .handle_packet(packet(DeployBridge::METHOD_EXECUTE))
            .expect("valid execute packet");
        assert_eq!(execute.value1(), Some(RESPONSE_ABORT));
    }

    #[test]
    fn exit_completes_with_packed_status() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0x00fe_0203;
        let response = bridge
            .handle_packet(
                packet(METHOD_EXIT)
                    .with_value1(packed)
                    .with_value2(0x8000_4005),
            )
            .expect("valid exit packet");

        assert_eq!(response.into_result(), Some(packed));
        assert_eq!(
            DeployStatus::decode(packed),
            DeployStatus {
                stage: DeployStage::DOWNLOAD,
                status: TerminalStatus::OPERATION_FAILED,
                detail: 2,
            }
        );
    }

    #[test]
    fn corrupt_terminal_values_are_preserved() {
        let bridge = DeployBridge::new(DeployPolicy::default());
        let packed = 0xab7c_5de6;

        let result = DeployStatus::decode(packed);
        assert_eq!(
            result,
            DeployStatus {
                stage: DeployStage(0xe6),
                status: TerminalStatus(0x7c),
                detail: 0x5d,
            }
        );
        assert_eq!(format!("{:?}", result.stage()), "230");
        assert_eq!(format!("{:?}", result.status()), "124");

        let response = bridge
            .handle_packet(packet(METHOD_EXIT).with_value1(packed))
            .expect("corrupt terminal values must produce a response");
        assert_eq!(response.into_result(), Some(packed));
    }
}
