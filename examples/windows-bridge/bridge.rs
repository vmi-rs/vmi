/// Packed status value carried by terminal bridge responses.
pub type BridgeStatusCode = u64;

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

/// Project stage encoded as one byte in a terminal result.
pub trait BridgeStage: Copy {
    /// Creates a stage from its raw bridge representation.
    fn from_raw(value: u8) -> Self;

    /// Returns the raw bridge representation.
    fn into_raw(self) -> u8;
}

/// Stable terminal status encoded by the shellcode or host bridge.
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

/// Terminal result decoded from the shared shellcode bridge format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalResult<Stage: BridgeStage> {
    /// Project stage that produced the result.
    stage: Stage,

    /// Stable result status.
    status: TerminalStatus,

    /// Stage-specific compact error code.
    code: u8,
}

impl<Stage: BridgeStage> TerminalResult<Stage> {
    /// Creates a result without a stage-specific error code.
    pub const fn new(stage: Stage, status: TerminalStatus) -> Self {
        Self {
            stage,
            status,
            code: 0,
        }
    }

    /// Returns the stage that produced the result.
    pub const fn stage(self) -> Stage {
        self.stage
    }

    /// Returns the stable result status.
    pub const fn status(self) -> TerminalStatus {
        self.status
    }

    /// Returns the stage-specific error code.
    pub const fn code(self) -> u8 {
        self.code
    }

    /// Encodes the result as a bridge status code.
    pub fn encode(self) -> BridgeStatusCode {
        let stage = self.stage.into_raw();

        stage as u64 | (self.status.0 as u64) << 8 | (self.code as u64) << 16
    }

    /// Decodes the packed result returned by the injector.
    pub fn decode(value: BridgeStatusCode) -> Self {
        Self {
            stage: Stage::from_raw(value as u8),
            status: TerminalStatus((value >> 8) as u8),
            code: (value >> 16) as u8,
        }
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

/// Implements `BridgeStage` for a one-field `u8` tuple newtype.
macro_rules! impl_bridge_stage {
    ($stage:ty) => {
        impl $crate::bridge::BridgeStage for $stage {
            fn from_raw(value: u8) -> Self {
                Self(value)
            }

            fn into_raw(self) -> u8 {
                self.0
            }
        }
    };
}

pub(crate) use impl_bridge_contract;
pub(crate) use impl_bridge_stage;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestStage(u8);

    impl_bridge_stage!(TestStage);

    #[test]
    fn bridge_stage_macro_preserves_raw_byte() {
        let stage = <TestStage as BridgeStage>::from_raw(0xa5);

        assert_eq!(stage, TestStage(0xa5));
        assert_eq!(stage.into_raw(), 0xa5);
    }

    #[test]
    fn terminal_result_encodes_protocol_bytes() {
        const RESULT: TerminalResult<TestStage> =
            TerminalResult::new(TestStage(0x05), TerminalStatus::WAITING);
        const STAGE: TestStage = RESULT.stage();
        const STATUS: TerminalStatus = RESULT.status();
        const CODE: u8 = RESULT.code();

        assert_eq!(RESULT.encode(), 0x0000_0105);
        assert_eq!(STAGE, TestStage(0x05));
        assert_eq!(STATUS, TerminalStatus::WAITING);
        assert_eq!(CODE, 0);
    }

    #[test]
    fn terminal_result_decodes_unknown_wire_values() {
        let result = TerminalResult::<TestStage>::decode(0xffff_ffff_ab5d_7ce6);

        assert_eq!(result.stage(), TestStage(0xe6));
        assert_eq!(result.status(), TerminalStatus(0x7c));
        assert_eq!(result.code(), 0x5d);
        assert_eq!(result.encode(), 0x005d_7ce6);
    }
}
