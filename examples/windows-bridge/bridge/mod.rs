mod kernel_mode;
mod user_mode;

use vmi::arch::amd64::Registers;

pub use self::{
    kernel_mode::{KernelShellcodeRecipeData, kernel_shellcode_recipe},
    user_mode::{UserShellcodeRecipeData, user_shellcode_recipe},
};

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

/// Cursor-based encoder for shellcode parameter wire formats.
///
/// Multi-byte scalar values are written little-endian. String methods append
/// their respective NUL terminators.
pub struct ParameterWriter<'a> {
    output: &'a mut Vec<u8>,
}

impl<'a> ParameterWriter<'a> {
    /// Creates a writer at the output's current cursor position.
    pub fn new(output: &'a mut Vec<u8>) -> Self {
        Self { output }
    }

    /// Writes bytes unchanged.
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
    }

    /// Writes a little-endian signed 8-bit integer.
    #[expect(unused)]
    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 8-bit integer.
    pub fn write_u8(&mut self, value: u8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 16-bit integer.
    #[expect(unused)]
    pub fn write_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 16-bit integer.
    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 32-bit integer.
    pub fn write_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 32-bit integer.
    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 64-bit integer.
    #[expect(unused)]
    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 64-bit integer.
    #[expect(unused)]
    pub fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes the string bytes unchanged followed by a NUL byte.
    ///
    /// This method does not transcode the value to a target ANSI code page.
    pub fn write_string(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
        self.write_u8(0);
    }

    /// Writes UTF-16LE code units followed by a NUL code unit.
    pub fn write_string_utf16(&mut self, value: &str) {
        for unit in value.encode_utf16() {
            self.write_bytes(&unit.to_le_bytes());
        }
        self.write_u16(0);
    }
}

/// Encodes one shellcode parameter block and declares its required alignment.
pub trait ShellcodeParameters {
    /// Alignment required for the parameter block's first byte.
    const ALIGNMENT: usize;

    /// Appends the exact parameter block while preserving existing output bytes.
    fn encode(&self, writer: &mut ParameterWriter);
}

/// Resolved parameter passed to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeParameter {
    /// Offset relative to the guest shellcode allocation.
    Offset(u64),

    /// Exact value passed to the shellcode.
    Value(u64),
}

/// Exact value to pass to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellcodeParameterValue(pub u64);

/// Resolves a shellcode parameter from appended data or an exact value.
pub trait ShellcodeParameterSource {
    /// Optionally appends parameter data and returns the resolved parameter.
    fn resolve(self, payload: &mut Vec<u8>) -> ShellcodeParameter;
}

impl<Parameters> ShellcodeParameterSource for &Parameters
where
    Parameters: ShellcodeParameters + ?Sized,
{
    fn resolve(self, payload: &mut Vec<u8>) -> ShellcodeParameter {
        debug_assert!(
            Parameters::ALIGNMENT.is_power_of_two(),
            "shellcode parameter alignment must be a nonzero power of two"
        );

        // Align the parameter block within the shellcode payload.
        let parameter_offset = payload.len().next_multiple_of(Parameters::ALIGNMENT);
        payload.resize(parameter_offset, 0);

        // Append the encoded parameters at the aligned offset.
        let mut writer = ParameterWriter::new(payload);
        self.encode(&mut writer);

        ShellcodeParameter::Offset(parameter_offset as u64)
    }
}

impl ShellcodeParameterSource for ShellcodeParameterValue {
    fn resolve(self, _payload: &mut Vec<u8>) -> ShellcodeParameter {
        ShellcodeParameter::Value(self.0)
    }
}

/// Encodes a standalone parameter block for test assertions.
#[cfg(test)]
pub fn encode_parameters(parameters: &impl ShellcodeParameters) -> Vec<u8> {
    let mut output = Vec::new();
    parameters.encode(&mut ParameterWriter::new(&mut output));
    output
}

/// Prepared bytes and metadata shared by user- and kernel-mode recipes.
#[derive(Debug)]
struct ShellcodePayload {
    bytes: Vec<u8>,
    parameter: ShellcodeParameter,
}

impl ShellcodePayload {
    fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        let mut bytes = shellcode.as_ref().to_vec();
        let parameter = parameter.resolve(&mut bytes);

        Self { bytes, parameter }
    }

    fn parameter_value(&self, allocation_base: u64) -> u64 {
        match self.parameter {
            ShellcodeParameter::Offset(offset) => allocation_base + offset,
            ShellcodeParameter::Value(value) => value,
        }
    }
}

/// Original register state retained across recoverable recipe failures.
#[derive(Debug, Default)]
struct ShellcodeRetryState {
    attempt: u64,
    original_registers: Option<Registers>,
}

impl ShellcodeRetryState {
    fn begin_attempt(&mut self, registers: &mut Registers) -> u64 {
        match self.original_registers {
            Some(original_registers) => *registers = original_registers,
            None => self.original_registers = Some(*registers),
        }

        self.attempt += 1;
        self.attempt
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

    #[test]
    fn parameter_writer_writes_wire_values() {
        let mut output = Vec::new();
        let mut writer = ParameterWriter::new(&mut output);
        writer.write_u32(0x1122_3344);
        writer.write_i32(-2);
        writer.write_string("A");
        writer.write_string_utf16("B");
        writer.write_bytes(&[0x10, 0x20]);
        assert_eq!(
            output,
            [
                0x44, 0x33, 0x22, 0x11, // u32
                0xfe, 0xff, 0xff, 0xff, // i32
                b'A', 0x00, // byte string
                b'B', 0x00, 0x00, 0x00, // UTF-16 string
                0x10, 0x20, // raw bytes
            ]
        );
    }

    struct FourByteParameters;

    impl ShellcodeParameters for FourByteParameters {
        const ALIGNMENT: usize = 4;

        fn encode(&self, writer: &mut ParameterWriter<'_>) {
            writer.write_bytes(&[0x11, 0x22]);
        }
    }

    #[test]
    fn payload_aligns_parameters_without_padding_stored_bytes() {
        const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];

        let payload = ShellcodePayload::new(SHELLCODE, &FourByteParameters);

        assert_eq!(payload.parameter, ShellcodeParameter::Offset(4));
        assert_eq!(&payload.bytes[..SHELLCODE.len()], SHELLCODE);
        assert_eq!(payload.bytes[SHELLCODE.len()], 0);
        assert_eq!(&payload.bytes[4..], &[0x11, 0x22]);
        assert_eq!(payload.bytes.len(), 6);
    }

    #[test]
    fn already_aligned_parameter_offset_is_unchanged() {
        let payload = ShellcodePayload::new(&[0xaa, 0xbb, 0xcc, 0xdd], &FourByteParameters);

        assert_eq!(payload.parameter, ShellcodeParameter::Offset(4));
    }

    #[test]
    fn direct_parameter_value_does_not_append_data() {
        const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];
        const PARAMETER: u64 = 0x1122_3344_5566_7788;

        let payload = ShellcodePayload::new(SHELLCODE, ShellcodeParameterValue(PARAMETER));

        assert_eq!(payload.parameter, ShellcodeParameter::Value(PARAMETER));
        assert_eq!(payload.bytes, SHELLCODE);
        assert_eq!(payload.parameter_value(0x1000), PARAMETER);
    }

    #[test]
    fn payload_offset_resolves_against_each_allocation() {
        let payload = ShellcodePayload::new(&[0xaa, 0xbb, 0xcc], &FourByteParameters);

        assert_eq!(payload.parameter_value(0x1000), 0x1004);
        assert_eq!(payload.parameter_value(0x2000), 0x2004);
    }

    #[test]
    fn retry_state_captures_then_restores_registers() {
        let mut retry = ShellcodeRetryState::default();
        let original = Registers {
            rax: 1,
            rsp: 2,
            rip: 3,
            ..Registers::default()
        };
        let mut registers = original;

        assert_eq!(retry.begin_attempt(&mut registers), 1);
        assert_eq!(retry.original_registers, Some(original));

        registers.rax = 10;
        registers.rsp = 20;
        registers.rip = 30;

        assert_eq!(retry.begin_attempt(&mut registers), 2);
        assert_eq!(registers, original);
    }

    struct ZeroAlignedParameters;

    impl ShellcodeParameters for ZeroAlignedParameters {
        const ALIGNMENT: usize = 0;

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
    }

    struct ThreeByteAlignedParameters;

    impl ShellcodeParameters for ThreeByteAlignedParameters {
        const ALIGNMENT: usize = 3;

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_zero_parameter_alignment() {
        ShellcodePayload::new(&[0xaa], &ZeroAlignedParameters);
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_non_power_of_two_parameter_alignment() {
        ShellcodePayload::new(&[0xaa], &ThreeByteAlignedParameters);
    }
}
