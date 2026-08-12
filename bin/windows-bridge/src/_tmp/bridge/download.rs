use deto_types::{VmiContext, WindowsOs};
use vmi::{
    Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        injector::InjectorStatusCode,
    },
};

use crate::{
    BRIDGE_METHOD_ERROR, BRIDGE_METHOD_EXIT, BRIDGE_RESPONSE_ABORT, BRIDGE_RESPONSE_CONTINUE,
    impl_bridge_contract,
};

#[derive(Default)]
pub enum ExecutePolicy {
    #[default]
    Continue,
    Wait,
}

#[derive(Default)]
pub struct InjectorDownloadBridge {
    max_download_attempts: u32,
    execute_policy: ExecutePolicy,
}

impl InjectorDownloadBridge {
    const RESPONSE_CONTINUE: u64 = BRIDGE_RESPONSE_CONTINUE;
    const RESPONSE_ABORT: u64 = BRIDGE_RESPONSE_ABORT;
    const RESPONSE_WAIT: u64 = 0x00000001;

    const METHOD_DOWNLOAD: u16 = 0x0001;
    const METHOD_EXTRACT: u16 = 0x0002;
    const METHOD_EXECUTE: u16 = 0x0003;
    const METHOD_ERROR: u16 = BRIDGE_METHOD_ERROR;
    const METHOD_EXIT: u16 = BRIDGE_METHOD_EXIT;

    pub fn with_max_download_attempts(self, max_download_attempts: u32) -> Self {
        Self {
            max_download_attempts,
            ..self
        }
    }

    pub fn with_execute_policy(self, execute_policy: ExecutePolicy) -> Self {
        Self {
            execute_policy,
            ..self
        }
    }
}

impl_bridge_contract!(InjectorDownloadBridge);

impl BridgeHandler<WindowsOs, InjectorStatusCode> for InjectorDownloadBridge {
    const REQUEST: u16 = 0x0001;

    #[tracing::instrument(name = "injector-p1", skip_all)]
    fn handle(
        &mut self,
        _vmi: &VmiContext,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<InjectorStatusCode>> {
        debug_assert_eq!(packet.request(), Self::REQUEST);

        match packet.method() {
            Self::METHOD_DOWNLOAD => {
                let attempt = packet.value1() as u32;

                tracing::debug!(attempt, "METHOD_DOWNLOAD");

                if attempt > self.max_download_attempts {
                    tracing::error!(
                        attempt,
                        max_download_attempts = self.max_download_attempts,
                        "download attempt limit reached"
                    );

                    return Some(BridgeResponse::new(Self::RESPONSE_ABORT));
                }

                Some(BridgeResponse::new(Self::RESPONSE_CONTINUE))
            }

            Self::METHOD_EXTRACT => {
                tracing::debug!("METHOD_EXTRACT");

                Some(BridgeResponse::new(Self::RESPONSE_CONTINUE))
            }

            Self::METHOD_EXECUTE => {
                tracing::debug!("METHOD_EXECUTE");

                let response = match self.execute_policy {
                    ExecutePolicy::Continue => BridgeResponse::new(Self::RESPONSE_CONTINUE),
                    ExecutePolicy::Wait => BridgeResponse::new(Self::RESPONSE_WAIT).with_result(0),
                };

                Some(response)
            }

            Self::METHOD_ERROR => {
                tracing::error!(
                    error_code = %Hex(packet.value1()),
                    value2 = %Hex(packet.value2()),
                    value3 = %Hex(packet.value3()),
                    value4 = %Hex(packet.value4()),
                    "METHOD_ERROR"
                );

                None
            }

            Self::METHOD_EXIT => {
                tracing::debug!(
                    exit_code = %Hex(packet.value1()),
                    value2 = %Hex(packet.value2()),
                    value3 = %Hex(packet.value3()),
                    value4 = %Hex(packet.value4()),
                    "METHOD_EXIT"
                );

                Some(BridgeResponse::default().with_result(0))
            }

            _ => {
                tracing::error!(
                    request = %Hex(packet.request()),
                    method = %Hex(packet.method()),
                    value1 = %Hex(packet.value1()),
                    value2 = %Hex(packet.value2()),
                    value3 = %Hex(packet.value3()),
                    value4 = %Hex(packet.value4()),
                    "METHOD_UNKNOWN"
                );

                None
            }
        }
    }
}