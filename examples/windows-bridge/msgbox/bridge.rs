use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::bridge::{BridgeHandler, BridgePacket, BridgeResponse},
};

use crate::bridge::{BridgeStatusCode, METHOD_EXIT, impl_bridge_contract};

/// Handles the result returned by `MessageBoxA`.
#[derive(Debug, Default)]
pub struct MsgboxBridge;

impl_bridge_contract!(MsgboxBridge);

impl MsgboxBridge {
    /// Terminal result method.
    const METHOD_EXIT: u16 = METHOD_EXIT;

    /// Handles one msgbox bridge packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        match packet.method() {
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Completes the injector from a terminal message box packet.
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        let result = packet.value1();
        tracing::debug!(result, "msgbox shellcode completed");

        Some(BridgeResponse::default().with_result(packet.value1()))
    }

    /// Logs and rejects one packet with an unknown msgbox bridge method.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        tracing::error!(
            request = %Hex(packet.request()),
            method = %Hex(packet.method()),
            value1 = %Hex(packet.value1()),
            value2 = %Hex(packet.value2()),
            value3 = %Hex(packet.value3()),
            value4 = %Hex(packet.value4()),
            "unknown msgbox bridge method"
        );

        None
    }
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, BridgeStatusCode> for MsgboxBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    /// Msgbox bridge request identifier.
    const REQUEST: u16 = 0x0002;

    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<BridgeStatusCode>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>, BridgeStatusCode>>::REQUEST
        );

        self.handle_packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use vmi::utils::bridge::BridgeContract;

    use super::*;
    use crate::bridge::BRIDGE_MAGIC;

    /// Creates one msgbox bridge packet.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, 0x0002, method)
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
            .handle_packet(packet(METHOD_EXIT).with_value1(1))
            .expect("exit packet should be handled");

        assert_eq!(response.into_result(), Some(1));
    }
}
