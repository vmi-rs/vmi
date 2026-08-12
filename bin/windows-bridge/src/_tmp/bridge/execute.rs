use std::{cell::Cell, rc::Rc};

use deto_types::{VmiContext, WindowsOs};
use vmi::{
    Hex,
    utils::bridge::{BridgeHandler, BridgePacket, BridgeResponse},
};

use crate::{BRIDGE_RESPONSE_CONTINUE, BridgeResult, impl_bridge_contract};

enum BridgeState {
    Open,
    Closed,
}

pub struct InjectorExecuteBridge {
    state: BridgeState,

    /// The execution is not allowed to proceed until this is set to true.
    ///
    /// This is used to synchronize with the initial environment fetching phase.
    fuse: Rc<Cell<bool>>,
}

impl InjectorExecuteBridge {
    const RESPONSE_CONTINUE: u64 = BRIDGE_RESPONSE_CONTINUE;
    const RESPONSE_WAIT: u64 = 0x00000001;

    const METHOD_EXECUTE: u16 = 0x0003;

    pub fn new(fuse: Rc<Cell<bool>>) -> Self {
        Self {
            state: BridgeState::Open,
            fuse,
        }
    }
}

impl_bridge_contract!(InjectorExecuteBridge);

impl BridgeHandler<WindowsOs, BridgeResult> for InjectorExecuteBridge {
    const REQUEST: u16 = 0x0001;

    #[tracing::instrument(name = "injector", skip_all)]
    fn handle(
        &mut self,
        _vmi: &VmiContext,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeResult>> {
        debug_assert_eq!(packet.request(), Self::REQUEST);

        if !matches!(self.state, BridgeState::Open) {
            tracing::error!("bridge is closed");

            return None;
        }

        match packet.method() {
            Self::METHOD_EXECUTE => {
                if self.fuse.get() {
                    tracing::debug!("last phase request");
                    self.state = BridgeState::Closed;

                    Some(BridgeResponse::new(Self::RESPONSE_CONTINUE))
                }
                else {
                    tracing::debug!("execution postponed");

                    Some(BridgeResponse::new(Self::RESPONSE_WAIT))
                }
            }

            _ => {
                tracing::error!(
                    request = %Hex(packet.request()),
                    method = %Hex(packet.method()),
                    value1 = %Hex(packet.value1()),
                    value2 = %Hex(packet.value2()),
                    value3 = %Hex(packet.value3()),
                    value4 = %Hex(packet.value4()),
                    "unknown method"
                );

                None
            }
        }
    }
}