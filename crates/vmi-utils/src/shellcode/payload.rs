#[cfg(any(test, all(feature = "arch-amd64", feature = "os-windows")))]
use vmi_core::Va;

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
    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 8-bit integer.
    pub fn write_u8(&mut self, value: u8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian signed 16-bit integer.
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
    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a little-endian unsigned 64-bit integer.
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

#[cfg(any(test, all(feature = "arch-amd64", feature = "os-windows")))]
/// Prepared bytes and metadata shared by shellcode recipes.
#[derive(Debug)]
pub struct ShellcodePayload {
    pub bytes: Vec<u8>,
    parameter: ShellcodeParameter,
}

#[cfg(any(test, all(feature = "arch-amd64", feature = "os-windows")))]
impl ShellcodePayload {
    pub fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        let mut bytes = shellcode.as_ref().to_vec();
        let parameter = parameter.resolve(&mut bytes);

        Self { bytes, parameter }
    }

    pub fn parameter_value(&self, allocation_base: Va) -> u64 {
        match self.parameter {
            ShellcodeParameter::Offset(offset) => allocation_base.0 + offset,
            ShellcodeParameter::Value(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(payload.parameter_value(Va(0x1000)), PARAMETER);
    }

    #[test]
    fn payload_offset_resolves_against_each_allocation() {
        let payload = ShellcodePayload::new(&[0xaa, 0xbb, 0xcc], &FourByteParameters);

        assert_eq!(payload.parameter_value(Va(0x1000)), 0x1004);
        assert_eq!(payload.parameter_value(Va(0x2000)), 0x2004);
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
