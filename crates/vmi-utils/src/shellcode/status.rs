/// Encoded status reported by shellcode.
///
/// The error code describes what went wrong in the current stage. The native
/// code contains the 32-bit error code from a system or library call.
///
/// ```text
/// +---------------------+----------+------------+----------+----------+
/// |        63-32        |  31-24   |   23-16    |   15-8   |   7-0    |
/// +---------------------+----------+------------+----------+----------+
/// |     Native code     | Reserved | Error code |   Kind   |  Stage   |
/// +---------------------+----------+------------+----------+----------+
/// ```
pub type EncodedStatus = u64;

/// Stage value encoded in a shellcode status.
pub trait Stage: Copy {
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
pub struct Status<StageType: Stage> {
    /// Stage associated with the status.
    stage: StageType,

    /// Status kind reported for the stage.
    kind: StatusKind,

    /// Stage-specific error code.
    code: u8,

    /// Native error code from a system or library call.
    native_code: u32,
}

impl<StageType: Stage> Status<StageType> {
    /// Creates a status without error codes.
    pub const fn new(stage: StageType, kind: StatusKind) -> Self {
        Self {
            stage,
            kind,
            code: 0,
            native_code: 0,
        }
    }

    /// Returns the stage associated with the status.
    pub const fn stage(self) -> StageType {
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

    /// Returns the native error code.
    pub const fn native_code(self) -> u32 {
        self.native_code
    }

    /// Encodes the status.
    pub fn encode(self) -> EncodedStatus {
        let stage = self.stage.into_raw();

        stage as u64
            | (self.kind.0 as u64) << 8
            | (self.code as u64) << 16
            | (self.native_code as u64) << 32
    }

    /// Decodes an encoded status.
    pub fn decode(value: EncodedStatus) -> Self {
        Self {
            stage: StageType::from_raw(value as u8),
            kind: StatusKind((value >> 8) as u8),
            code: (value >> 16) as u8,
            native_code: (value >> 32) as u32,
        }
    }
}

/// Implements [`Stage`] for a tuple struct containing one `u8`.
#[doc(hidden)]
#[macro_export]
macro_rules! _private_impl_stage {
    ($stage:ty) => {
        impl $crate::shellcode::Stage for $stage {
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
pub use _private_impl_stage as impl_stage;
