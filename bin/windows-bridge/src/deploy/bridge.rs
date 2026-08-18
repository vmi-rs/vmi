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

use crate::bridge::{METHOD_EXIT, RESPONSE_ABORT, RESPONSE_CONTINUE, impl_bridge_contract};

/// Deploy operation stage encoded in a terminal status.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DeployStage(u8);

impl DeployStage {
    /// No operation ran.
    const NONE: Self = Self(0x00);

    /// Parameter parsing failed.
    const PARAMETERS: Self = Self(0x01);

    /// Initialization failed.
    const INITIALIZATION: Self = Self(0x02);

    /// Download completed or failed.
    const DOWNLOAD: Self = Self(0x03);

    /// Extraction completed or failed.
    const EXTRACT: Self = Self(0x04);

    /// Execution completed or failed.
    const EXECUTE: Self = Self(0x05);
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

/// Stable terminal status encoded by the deploy shellcode.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DeployTerminalStatus(u8);

impl DeployTerminalStatus {
    /// The requested stages completed successfully.
    const SUCCESS: Self = Self(0x00);

    /// The serialized parameters were invalid.
    const INVALID_PARAMETERS: Self = Self(0xfd);

    /// A guest operation failed.
    const OPERATION_FAILED: Self = Self(0xfe);

    /// The host aborted a gated stage.
    const ABORTED: Self = Self(0xff);
}

impl std::fmt::Debug for DeployTerminalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::SUCCESS => "Success",
            Self::INVALID_PARAMETERS => "InvalidParameters",
            Self::OPERATION_FAILED => "OperationFailed",
            Self::ABORTED => "Aborted",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Decoded status returned by the injector after a terminal bridge packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeployStatus {
    /// Stage that produced the terminal result.
    stage: DeployStage,

    /// Stable terminal status.
    status: DeployTerminalStatus,

    /// Stage-specific compact detail code.
    detail: u8,
}

impl DeployStatus {
    /// Decodes the packed status returned by the injector.
    pub(crate) fn decode(value: InjectorStatusCode) -> Self {
        Self {
            stage: DeployStage(value as u8),
            status: DeployTerminalStatus((value >> 16) as u8),
            detail: (value >> 8) as u8,
        }
    }

    /// Returns whether all requested stages completed successfully.
    pub(crate) fn is_success(self) -> bool {
        self.status == DeployTerminalStatus::SUCCESS
    }

    /// Returns the stage that produced the result.
    fn stage(self) -> DeployStage {
        self.stage
    }

    /// Returns the stable terminal status.
    fn status(self) -> DeployTerminalStatus {
        self.status
    }

    /// Returns the stage-specific detail code.
    fn detail(self) -> u8 {
        self.detail
    }
}

/// Host-side limits and permissions for a deploy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeployPolicy {
    /// Number of retries allowed after failed download attempts.
    max_download_retries: u64,

    /// Whether the host permits archive extraction.
    allow_extract: bool,

    /// Whether the host permits process execution.
    allow_execute: bool,
}

impl DeployPolicy {
    /// Creates an explicit deploy policy.
    pub(crate) fn new(max_download_retries: u64, allow_extract: bool, allow_execute: bool) -> Self {
        Self {
            max_download_retries,
            allow_extract,
            allow_execute,
        }
    }
}

/// Handles deploy stage gates and the terminal shellcode result.
#[derive(Debug)]
pub(crate) struct DeployBridge {
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
    pub(crate) fn new(policy: DeployPolicy) -> Self {
        Self { policy }
    }

    /// Produces the protocol response for one deploy packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        match packet.method() {
            Self::METHOD_DOWNLOAD => self.handle_download(packet),
            Self::METHOD_EXTRACT => self.handle_extract(packet),
            Self::METHOD_EXECUTE => self.handle_execute(packet),
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => {
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
    }

    /// Applies the download retry limit to a readiness or failure report.
    fn handle_download(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let attempt = packet.value1();
        let response = if attempt == 0 || attempt <= self.policy.max_download_retries {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        };

        tracing::debug!(
            attempt,
            native_code = packet.value2(),
            response,
            "deploy download gate"
        );

        Some(BridgeResponse::new(response))
    }
    /// Applies the extraction policy to an extraction gate.
    fn handle_extract(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        self.stage_response(packet, self.policy.allow_extract, "extract")
    }

    /// Applies the execution policy to an execution gate.
    fn handle_execute(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        self.stage_response(packet, self.policy.allow_execute, "execute")
    }

    /// Applies an independent host permission to an extraction or execution gate.
    fn stage_response(
        &self,
        _packet: BridgePacket,
        allowed: bool,
        stage: &'static str,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        let response = if allowed {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        };

        tracing::debug!(stage, allowed, "deploy stage gate");
        Some(BridgeResponse::new(response))
    }

    /// Completes the injector from a terminal result packet.
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        let result = DeployStatus::decode(packet.value1());

        tracing::debug!(
            stage = ?result.stage(),
            status = ?result.status(),
            detail = result.detail(),
            native_code = packet.value2(),
            "deploy shellcode completed"
        );

        Some(BridgeResponse::default().with_result(packet.value1()))
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
    fn download_gate_enforces_retry_boundary() {
        let bridge = DeployBridge::new(DeployPolicy::new(2, false, false));

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
        let bridge = DeployBridge::new(DeployPolicy::new(0, false, true));

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
    fn exit_completes_with_packed_status() {
        let bridge = DeployBridge::new(DeployPolicy::new(0, false, false));
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
                status: DeployTerminalStatus::OPERATION_FAILED,
                detail: 2,
            }
        );
    }

    #[test]
    fn corrupt_terminal_values_are_preserved() {
        let bridge = DeployBridge::new(DeployPolicy::new(0, false, false));
        let packed = 0xab7c_5de6;

        let result = DeployStatus::decode(packed);
        assert_eq!(
            result,
            DeployStatus {
                stage: DeployStage(0xe6),
                status: DeployTerminalStatus(0x7c),
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
