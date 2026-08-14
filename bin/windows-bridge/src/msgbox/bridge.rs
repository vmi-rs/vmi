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

/// Msgbox bridge request identifier.
const REQUEST_MSGBOX: u16 = 0x0002;

/// Little-endian ASCII `VMI-RS3!` response signature.
const VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Little-endian ASCII `VMI-RS4!` response signature.
const VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Terminal result method.
const METHOD_EXIT: u16 = 0xffff;

/// Handles the result returned by `MessageBoxA`.
#[derive(Debug, Default)]
pub(crate) struct MsgboxBridge;

impl MsgboxBridge {
    /// Completes the injector from a terminal message box packet.
    fn respond(&self, packet: BridgePacket) -> Option<BridgeResponse<InjectorStatusCode>> {
        if packet.method() != METHOD_EXIT
            || packet.value2() != 0
            || packet.value3() != 0
            || packet.value4() != 0
        {
            return None;
        }

        tracing::debug!(result = packet.value1(), "msgbox shellcode completed");
        Some(BridgeResponse::default().with_result(packet.value1()))
    }
}

impl BridgeContract for MsgboxBridge {
    const MAGIC: Option<u32> = Some(BRIDGE_MAGIC);
    const VERIFY_VALUE3: Option<u64> = Some(VERIFY_VALUE3);
    const VERIFY_VALUE4: Option<u64> = Some(VERIFY_VALUE4);
}

impl<Driver> BridgeHandler<WindowsOs<Driver>, InjectorStatusCode> for MsgboxBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    const REQUEST: u16 = REQUEST_MSGBOX;

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

    /// Creates one msgbox bridge packet.
    fn packet(method: u16) -> BridgePacket {
        BridgePacket::new(BRIDGE_MAGIC, REQUEST_MSGBOX, method)
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
    fn exit_completes_with_message_box_result() {
        let response = MsgboxBridge
            .respond(packet(METHOD_EXIT).with_value1(1))
            .expect("exit packet should be handled");

        assert_eq!(response.into_result(), Some(1));
    }

    #[test]
    fn malformed_packets_produce_no_response() {
        assert!(MsgboxBridge.respond(packet(1)).is_none());
        assert!(
            MsgboxBridge
                .respond(packet(METHOD_EXIT).with_value2(1))
                .is_none()
        );
        assert!(
            MsgboxBridge
                .respond(packet(METHOD_EXIT).with_value3(1))
                .is_none()
        );
        assert!(
            MsgboxBridge
                .respond(packet(METHOD_EXIT).with_value4(1))
                .is_none()
        );
    }
}
