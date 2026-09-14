use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        shellcode::{BridgeStatusCode, impl_bridge_contract},
    },
};

/// Handles communication with the `msgbox` shellcode.
#[derive(Debug, Default)]
pub struct MsgboxBridge;

impl_bridge_contract!(MsgboxBridge);

impl MsgboxBridge {
    /// Method used to report the final result.
    const METHOD_EXIT: u16 = 0xffff;

    /// Handles a `msgbox` bridge packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        match packet.method() {
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Handles the [`METHOD_EXIT`] bridge method.
    ///
    /// [`METHOD_EXIT`]: Self::METHOD_EXIT
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        let result = packet.value1();

        tracing::debug!(result, "shellcode completed");

        Some(BridgeResponse::default().with_result(packet.value1()))
    }

    /// Handles a bridge packet with an unknown method.
    ///
    /// Logs the packet details and returns no response.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
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

impl<Driver> BridgeHandler<WindowsOs<Driver>> for MsgboxBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    type Output = BridgeStatusCode;

    /// Request code for the `msgbox` shellcode.
    const REQUEST: u16 = 0x0001;

    #[tracing::instrument(name = "msgbox", skip_all)]
    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeStatusCode>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>>>::REQUEST
        );

        self.handle_packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use vmi::utils::{bridge::BridgeContract, shellcode::BRIDGE_MAGIC};

    use super::*;

    /// Creates a msgbox bridge packet.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, 0x0001, method)
    }

    #[test]
    fn contract_matches_guest_constants() {
        assert_eq!(<MsgboxBridge as BridgeContract>::MAGIC, Some(0x4249_4d56));
        assert_eq!(
            <MsgboxBridge as BridgeContract>::VERIFY_VALUE3,
            Some(0x2133_5352_2d49_4d56)
        );
        assert_eq!(
            <MsgboxBridge as BridgeContract>::VERIFY_VALUE4,
            Some(0x2134_5352_2d49_4d56)
        );
    }

    #[test]
    fn unknown_method_is_not_handled() {
        assert!(MsgboxBridge.handle_unknown(packet(0x1234)).is_none());
        assert!(MsgboxBridge.handle_packet(packet(0x1234)).is_none());
    }

    #[test]
    fn exit_completes_with_message_box_result() {
        let response = MsgboxBridge
            .handle_packet(packet(MsgboxBridge::METHOD_EXIT).with_value1(1))
            .expect("exit packet should be handled");

        assert_eq!(response.into_result(), Some(1));
    }
}
