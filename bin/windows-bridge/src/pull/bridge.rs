use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    utils::{
        bridge::{BridgeContract, BridgeHandler, BridgePacket, BridgeResponse},
        injector::InjectorStatusCode,
    },
};

/// Little-endian ASCII `VMIB` bridge signature.
const BRIDGE_MAGIC: u32 = 0x4249_4d56;

/// Pull bridge request identifier.
const REQUEST_PULL: u16 = 0x0001;

/// Little-endian ASCII `VMI-RS3!` response signature.
const VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Little-endian ASCII `VMI-RS4!` response signature.
const VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Download readiness and retry method.
const METHOD_DOWNLOAD: u16 = 0x0001;

/// Extraction policy gate method.
const METHOD_EXTRACT: u16 = 0x0002;

/// Execution policy gate method.
const METHOD_EXECUTE: u16 = 0x0003;

/// Terminal result method.
const METHOD_EXIT: u16 = 0xffff;

/// Allows the shellcode to continue its current stage.
const RESPONSE_CONTINUE: u64 = 0x0000_0000;

/// Aborts the shellcode's current stage.
const RESPONSE_ABORT: u64 = 0xffff_ffff;

/// Pull operation stage encoded in a terminal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PullStage {
    /// No operation ran.
    None = 0x00,

    /// Parameter parsing failed.
    Parameters = 0x01,

    /// Initialization failed.
    Initialization = 0x02,

    /// Download completed or failed.
    Download = 0x03,

    /// Extraction completed or failed.
    Extract = 0x04,

    /// Execution completed or failed.
    Execute = 0x05,
}

impl PullStage {
    /// Decodes a protocol stage value.
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Parameters),
            0x02 => Some(Self::Initialization),
            0x03 => Some(Self::Download),
            0x04 => Some(Self::Extract),
            0x05 => Some(Self::Execute),
            _ => None,
        }
    }
}

/// Stable terminal status encoded by the pull shellcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PullTerminalStatus {
    /// The requested stages completed successfully.
    Success = 0x00,

    /// The serialized parameters were invalid.
    InvalidParameters = 0xfd,

    /// A guest operation failed.
    OperationFailed = 0xfe,

    /// The host aborted a gated stage.
    Aborted = 0xff,
}

impl PullTerminalStatus {
    /// Decodes a protocol terminal status value.
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Success),
            0xfd => Some(Self::InvalidParameters),
            0xfe => Some(Self::OperationFailed),
            0xff => Some(Self::Aborted),
            _ => None,
        }
    }
}

/// Decoded status returned by the injector after a terminal bridge packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PullStatus {
    /// Stage that produced the terminal result.
    stage: PullStage,

    /// Stable terminal status.
    status: PullTerminalStatus,

    /// Stage-specific compact detail code.
    detail: u8,
}

impl PullStatus {
    /// Decodes the packed status returned by the injector.
    pub(crate) const fn decode(value: InjectorStatusCode) -> Option<Self> {
        if value >> 24 != 0 {
            return None;
        }

        let stage = match PullStage::from_u8(value as u8) {
            Some(stage) => stage,
            None => return None,
        };

        let status = match PullTerminalStatus::from_u8((value >> 16) as u8) {
            Some(status) => status,
            None => return None,
        };

        Some(Self {
            stage,
            status,
            detail: (value >> 8) as u8,
        })
    }

    /// Returns the stage that produced the result.
    pub(crate) const fn stage(self) -> PullStage {
        self.stage
    }

    /// Returns the stable terminal status.
    pub(crate) const fn status(self) -> PullTerminalStatus {
        self.status
    }

    /// Returns the stage-specific detail code.
    pub(crate) const fn detail(self) -> u8 {
        self.detail
    }
}

/// Host-side limits and permissions for a pull request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PullPolicy {
    /// Number of retries allowed after failed download attempts.
    max_download_retries: u64,

    /// Whether the host permits archive extraction.
    allow_extract: bool,

    /// Whether the host permits process execution.
    allow_execute: bool,
}

impl PullPolicy {
    /// Creates an explicit pull policy.
    pub(crate) const fn new(
        max_download_retries: u64,
        allow_extract: bool,
        allow_execute: bool,
    ) -> Self {
        Self {
            max_download_retries,
            allow_extract,
            allow_execute,
        }
    }
}

/// Handles pull stage gates and the terminal shellcode result.
#[derive(Debug)]
pub(crate) struct PullBridge {
    /// Policy applied to shellcode requests.
    policy: PullPolicy,
}

impl PullBridge {
    /// Creates a pull bridge with the supplied host policy.
    pub(crate) const fn new(policy: PullPolicy) -> Self {
        Self { policy }
    }

    /// Produces the protocol response for one pull packet.
    fn respond(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        match packet.method() {
            METHOD_DOWNLOAD => self.download_response(packet),
            METHOD_EXTRACT => self.stage_response(packet, self.policy.allow_extract, "extract"),
            METHOD_EXECUTE => self.stage_response(packet, self.policy.allow_execute, "execute"),
            METHOD_EXIT => self.exit_response(packet),
            _ => None,
        }
    }

    /// Applies the download retry limit to a readiness or failure report.
    fn download_response(
        &self,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        if packet.value3() != 0 || packet.value4() != 0 {
            return None;
        }

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
            "pull download gate"
        );

        Some(BridgeResponse::new(response))
    }

    /// Applies an independent host permission to an extraction or execution gate.
    fn stage_response(
        &self,
        packet: BridgePacket,
        allowed: bool,
        stage: &'static str,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        if packet.value1() != 0
            || packet.value2() != 0
            || packet.value3() != 0
            || packet.value4() != 0
        {
            return None;
        }

        let response = if allowed {
            RESPONSE_CONTINUE
        }
        else {
            RESPONSE_ABORT
        };

        tracing::debug!(stage, allowed, "pull stage gate");
        Some(BridgeResponse::new(response))
    }

    /// Validates and completes the injector from a terminal result packet.
    fn exit_response(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        if packet.value3() != 0 || packet.value4() != 0 {
            return None;
        }

        let result = PullStatus::decode(packet.value1())?;
        tracing::debug!(
            stage = ?result.stage(),
            status = ?result.status(),
            detail = result.detail(),
            native_code = packet.value2(),
            "pull shellcode completed"
        );

        Some(BridgeResponse::default().with_result(packet.value1()))
    }
}

impl BridgeContract for PullBridge {
    const MAGIC: Option<u32> = Some(BRIDGE_MAGIC);
    const VERIFY_VALUE3: Option<u64> = Some(VERIFY_VALUE3);
    const VERIFY_VALUE4: Option<u64> = Some(VERIFY_VALUE4);
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, InjectorStatusCode> for PullBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    const REQUEST: u16 = REQUEST_PULL;

    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>, InjectorStatusCode>>::REQUEST
        );

        self.respond(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a packet routed to the pull handler.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, REQUEST_PULL, method)
    }

    #[test]
    fn contract_matches_guest_constants() {
        assert_eq!(<PullBridge as BridgeContract>::MAGIC, Some(0x4249_4d56));
        assert_eq!(
            <PullBridge as BridgeContract>::VERIFY_VALUE3,
            Some(0x2133_5352_2d49_4d56)
        );
        assert_eq!(
            <PullBridge as BridgeContract>::VERIFY_VALUE4,
            Some(0x2134_5352_2d49_4d56)
        );
    }

    #[test]
    fn download_gate_enforces_retry_boundary() {
        let bridge = PullBridge::new(PullPolicy::new(2, false, false));

        for attempt in [0, 1, 2] {
            let response = bridge
                .respond(packet(METHOD_DOWNLOAD).with_value1(attempt))
                .expect("valid download packet");
            assert_eq!(response.value1(), Some(RESPONSE_CONTINUE));
        }

        let response = bridge
            .respond(packet(METHOD_DOWNLOAD).with_value1(3))
            .expect("valid download packet");
        assert_eq!(response.value1(), Some(RESPONSE_ABORT));
    }

    #[test]
    fn stage_gates_apply_permissions_independently() {
        let bridge = PullBridge::new(PullPolicy::new(0, false, true));

        let extract = bridge
            .respond(packet(METHOD_EXTRACT))
            .expect("valid extract packet");
        assert_eq!(extract.value1(), Some(RESPONSE_ABORT));

        let execute = bridge
            .respond(packet(METHOD_EXECUTE))
            .expect("valid execute packet");
        assert_eq!(execute.value1(), Some(RESPONSE_CONTINUE));
    }

    #[test]
    fn exit_completes_with_packed_status() {
        let bridge = PullBridge::new(PullPolicy::new(0, false, false));
        let packed = 0x00fe_0203;
        let response = bridge
            .respond(
                packet(METHOD_EXIT)
                    .with_value1(packed)
                    .with_value2(0x8000_4005),
            )
            .expect("valid exit packet");

        assert_eq!(response.into_result(), Some(packed));
        assert_eq!(
            PullStatus::decode(packed),
            Some(PullStatus {
                stage: PullStage::Download,
                status: PullTerminalStatus::OperationFailed,
                detail: 2,
            })
        );
    }

    #[test]
    fn malformed_packets_produce_no_response() {
        let bridge = PullBridge::new(PullPolicy::new(0, true, true));

        assert!(
            bridge
                .respond(packet(METHOD_EXTRACT).with_value1(1))
                .is_none()
        );
        assert!(
            bridge
                .respond(packet(METHOD_EXIT).with_value1(1 << 24))
                .is_none()
        );
        assert!(bridge.respond(packet(0x1234)).is_none());
    }
}
