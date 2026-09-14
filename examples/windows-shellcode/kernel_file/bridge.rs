use vmi::{
    VmiContext,
    arch::amd64::Amd64,
    driver::VmiRead,
    os::windows::WindowsOs,
    trace::Hex,
    utils::{
        bridge::{BridgeHandler, BridgePacket, BridgeResponse},
        shellcode::{BridgeStatusCode, Status, impl_bridge_contract, impl_bridge_stage},
    },
};

/// Stage reported by the `kernel-file` shellcode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KernelFileStage(u8);

impl_bridge_stage!(KernelFileStage);

impl KernelFileStage {
    /// No file operation was started.
    pub const NONE: Self = Self(0x00);

    /// File creation stage.
    pub const CREATE: Self = Self(0x01);

    /// File writing stage.
    pub const WRITE: Self = Self(0x02);
}

impl std::fmt::Debug for KernelFileStage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::NONE => "None",
            Self::CREATE => "Create",
            Self::WRITE => "Write",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Status reported by the `kernel-file` shellcode.
pub type KernelFileStatus = Status<KernelFileStage>;

/// Handles communication with the `kernel-file` shellcode.
#[derive(Debug, Default)]
pub struct KernelFileBridge;

impl_bridge_contract!(KernelFileBridge);

impl KernelFileBridge {
    /// Method used to report the final status.
    const METHOD_EXIT: u16 = 0xffff;

    /// Handles a `kernel-file` bridge packet.
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
        let status = KernelFileStatus::decode(packet.value1());

        tracing::debug!(
            ?status,
            native_code = %Hex(packet.value2()),
            "shellcode completed"
        );

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

impl<Driver> BridgeHandler<WindowsOs<Driver>> for KernelFileBridge
where
    Driver: VmiRead<Architecture = Amd64>,
{
    type Output = BridgeStatusCode;

    /// Request code for the `kernel-file` shellcode.
    const REQUEST: u16 = 0x0002;

    #[tracing::instrument(name = "kernel_file", skip_all)]
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
