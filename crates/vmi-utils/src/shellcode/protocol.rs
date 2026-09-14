/// Magic value used to identify shellcode bridge requests (`VMIB`).
pub const BRIDGE_MAGIC: u32 = 0x4249_4d56;

/// Verification value expected in the 3rd bridge response field (`VMI-RS3!`).
pub const BRIDGE_VERIFY_VALUE3: u64 = 0x2133_5352_2d49_4d56;

/// Verification value expected in the 4th bridge response field (`VMI-RS4!`).
pub const BRIDGE_VERIFY_VALUE4: u64 = 0x2134_5352_2d49_4d56;

/// Packed shellcode status used by the bridge.
pub type BridgeStatusCode = u64;

/// Stage value encoded in a shellcode status.
pub trait BridgeStage: Copy {
    /// Creates a stage from its encoded byte.
    fn from_raw(value: u8) -> Self;

    /// Returns the encoded stage byte.
    fn into_raw(self) -> u8;
}

/// Status kind encoded in a shellcode status.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StatusKind(pub u8);

impl StatusKind {
    /// The stage completed successfully.
    pub const SUCCESS: Self = Self(0x00);

    /// The shellcode is waiting for the host to continue.
    pub const WAITING: Self = Self(0x01);

    /// The shellcode parameters were invalid.
    pub const INVALID_PARAMETERS: Self = Self(0xfd);

    /// An operation in the current stage failed.
    pub const OPERATION_FAILED: Self = Self(0xfe);

    /// The host aborted the current stage.
    pub const ABORTED: Self = Self(0xff);
}

impl std::fmt::Debug for StatusKind {
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

/// Status reported through the shellcode bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status<Stage: BridgeStage> {
    /// Stage associated with the status.
    stage: Stage,

    /// Status kind reported for the stage.
    kind: StatusKind,

    /// Stage-specific error code.
    code: u8,
}

impl<Stage: BridgeStage> Status<Stage> {
    /// Creates a status without an error code.
    pub const fn new(stage: Stage, kind: StatusKind) -> Self {
        Self {
            stage,
            kind,
            code: 0,
        }
    }

    /// Returns the stage associated with the status.
    pub const fn stage(self) -> Stage {
        self.stage
    }

    /// Returns the status kind.
    pub const fn kind(self) -> StatusKind {
        self.kind
    }

    /// Returns the stage-specific error code.
    pub const fn code(self) -> u8 {
        self.code
    }

    /// Encodes the status as a bridge status code.
    pub fn encode(self) -> BridgeStatusCode {
        let stage = self.stage.into_raw();

        stage as u64 | (self.kind.0 as u64) << 8 | (self.code as u64) << 16
    }

    /// Decodes a bridge status code.
    pub fn decode(value: BridgeStatusCode) -> Self {
        Self {
            stage: Stage::from_raw(value as u8),
            kind: StatusKind((value >> 8) as u8),
            code: (value >> 16) as u8,
        }
    }
}

/// Implements the shellcode bridge contract for a handler.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_impl_bridge_contract {
    ($bridge:ty) => {
        impl $crate::bridge::BridgeContract for $bridge {
            const MAGIC: Option<u32> = Some($crate::shellcode::BRIDGE_MAGIC);
            const VERIFY_VALUE3: Option<u64> = Some($crate::shellcode::BRIDGE_VERIFY_VALUE3);
            const VERIFY_VALUE4: Option<u64> = Some($crate::shellcode::BRIDGE_VERIFY_VALUE4);
        }
    };
}

/// Implements [`BridgeStage`] for a tuple struct containing one `u8`.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_impl_bridge_stage {
    ($stage:ty) => {
        impl $crate::shellcode::BridgeStage for $stage {
            fn from_raw(value: u8) -> Self {
                Self(value)
            }

            fn into_raw(self) -> u8 {
                self.0
            }
        }
    };
}

#[doc(inline)]
pub use _private_impl_bridge_contract as impl_bridge_contract;
#[doc(inline)]
pub use _private_impl_bridge_stage as impl_bridge_stage;

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
    fn terminal_status_encodes_protocol_bytes() {
        const STATUS: Status<TestStage> = Status::new(TestStage(0x05), StatusKind::WAITING);
        const STAGE: TestStage = STATUS.stage();
        const KIND: StatusKind = STATUS.kind();
        const CODE: u8 = STATUS.code();

        assert_eq!(STATUS.encode(), 0x0000_0105);
        assert_eq!(STAGE, TestStage(0x05));
        assert_eq!(KIND, StatusKind::WAITING);
        assert_eq!(CODE, 0);
    }

    #[test]
    fn terminal_status_decodes_unknown_wire_values() {
        let status = Status::<TestStage>::decode(0xffff_ffff_ab5d_7ce6);

        assert_eq!(status.stage(), TestStage(0xe6));
        assert_eq!(status.kind(), StatusKind(0x7c));
        assert_eq!(status.code(), 0x5d);
        assert_eq!(status.encode(), 0x005d_7ce6);
    }
}
