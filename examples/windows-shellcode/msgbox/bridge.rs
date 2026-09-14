use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        shellcode::impl_bridge_contract,
    },
};

/// Host-side bridge handler for the `msgbox` shellcode.
#[derive(Debug, Default)]
pub struct MsgboxBridge;

impl_bridge_contract!(MsgboxBridge);

impl MsgboxBridge {
    /// Method used to report the final result.
    const METHOD_EXIT: u16 = 0xffff;

    /// Handles a `msgbox` bridge packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<u64>> {
        match packet.method() {
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Handles the [`METHOD_EXIT`] bridge method.
    ///
    /// [`METHOD_EXIT`]: Self::METHOD_EXIT
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<u64>> {
        let result = packet.value1();

        tracing::debug!(result, "shellcode completed");

        Some(BridgeResponse::default().with_output(packet.value1()))
    }

    /// Handles a bridge packet with an unknown method.
    ///
    /// Logs the packet details and returns no response.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<u64>> {
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
    /// Return value of the `MessageBoxA` function.
    type Output = u64;

    /// Request code for the `msgbox` shellcode.
    const REQUEST: u16 = 0x0001;

    #[tracing::instrument(name = "msgbox", skip_all)]
    fn handle(
        &mut self,
        _vmi: &VmiContext<'_, WindowsOs<Driver>>,
        packet: BridgePacket,
    ) -> Option<BridgeResponse<u64>> {
        debug_assert_eq!(
            packet.request(),
            <Self as BridgeHandler<WindowsOs<Driver>>>::REQUEST
        );

        self.handle_packet(packet)
    }
}
