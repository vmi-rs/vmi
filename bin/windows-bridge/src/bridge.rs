/// Little-endian ASCII `VMIB` bridge signature.
pub const BRIDGE_MAGIC: u32 = 0x4249_4d56;

/// Little-endian ASCII `VMI-RS3!` response signature.
pub const VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Little-endian ASCII `VMI-RS4!` response signature.
pub const VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Terminal result method.
pub const METHOD_EXIT: u16 = 0xffff;

/// Allows the shellcode to continue its current stage.
pub const RESPONSE_CONTINUE: u64 = 0x0000_0000;

/// Leaves the shellcode waiting at its current stage.
pub const RESPONSE_WAIT: u64 = 0x0000_0001;

/// Aborts the shellcode's current stage.
pub const RESPONSE_ABORT: u64 = 0xffff_ffff;

/// Stable deploy status encoded by the shellcode or host bridge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TerminalStatus(pub u8);

impl TerminalStatus {
    /// The requested stages completed successfully.
    pub const SUCCESS: Self = Self(0x00);

    /// The host bridge detached while the shellcode remains parked.
    pub const WAITING: Self = Self(0x01);

    /// The serialized parameters were invalid.
    pub const INVALID_PARAMETERS: Self = Self(0xfd);

    /// A guest operation failed.
    pub const OPERATION_FAILED: Self = Self(0xfe);

    /// The host aborted a gated stage.
    pub const ABORTED: Self = Self(0xff);
}

impl std::fmt::Debug for TerminalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::SUCCESS => "Success",
            Self::WAITING => "Waiting",
            Self::INVALID_PARAMETERS => "InvalidParameters",
            Self::OPERATION_FAILED => "OperationFailed",
            Self::ABORTED => "Aborted",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Implements the shared shellcode bridge contract for a handler.
macro_rules! impl_bridge_contract {
    ($bridge:ty) => {
        impl vmi::utils::bridge::BridgeContract for $bridge {
            const MAGIC: Option<u32> = Some($crate::bridge::BRIDGE_MAGIC);
            const VERIFY_VALUE3: Option<u64> = Some($crate::bridge::VERIFY_VALUE3);
            const VERIFY_VALUE4: Option<u64> = Some($crate::bridge::VERIFY_VALUE4);
        }
    };
}

pub(crate) use impl_bridge_contract;
