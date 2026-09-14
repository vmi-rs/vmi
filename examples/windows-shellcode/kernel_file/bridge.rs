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

/// Kernel-file operation stage encoded in a packed status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KernelFileStage(u8);

impl_bridge_stage!(KernelFileStage);

impl KernelFileStage {
    /// No operation ran.
    pub const NONE: Self = Self(0x00);

    /// File creation completed or failed.
    pub const CREATE: Self = Self(0x01);

    /// Content write completed or failed.
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

/// Decoded status returned by the injector handler.
pub type KernelFileStatus = Status<KernelFileStage>;

/// Handles the terminal status reported by the kernel-file shellcode.
#[derive(Debug, Default)]
pub struct KernelFileBridge;

impl_bridge_contract!(KernelFileBridge);

impl KernelFileBridge {
    /// Terminal result method.
    const METHOD_EXIT: u16 = 0xffff;

    /// Handles one kernel-file bridge packet.
    fn handle_packet(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        match packet.method() {
            Self::METHOD_EXIT => self.handle_exit(packet),
            _ => self.handle_unknown(packet),
        }
    }

    /// Completes the injector from a terminal kernel-file packet.
    fn handle_exit(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        let status = KernelFileStatus::decode(packet.value1());

        tracing::debug!(
            ?status,
            native_code = %Hex(packet.value2()),
            "shellcode completed"
        );

        Some(BridgeResponse::default().with_result(packet.value1()))
    }

    /// Logs and rejects one packet with an unknown kernel-file bridge method.
    fn handle_unknown(&self, packet: BridgePacket) -> Option<BridgeResponse<BridgeStatusCode>> {
        tracing::error!(
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

    /// Kernel-file bridge request identifier.
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
