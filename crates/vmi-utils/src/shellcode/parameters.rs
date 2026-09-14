/// Append-only encoder for shellcode parameters.
///
/// Multi-byte scalar values are written little-endian. String methods append
/// their respective NUL terminators. Fields are packed without internal
/// padding. [`Parameters::ALIGNMENT`] aligns the whole block within
/// the payload.
///
/// The guest-side `sc::vmi::parameter_reader` reads the encoded block.
pub struct ParameterWriter<'a> {
    /// Output buffer for appending parameter bytes.
    output: &'a mut Vec<u8>,
}

impl<'a> ParameterWriter<'a> {
    /// Creates a writer that appends to the given output buffer.
    pub fn new(output: &'a mut Vec<u8>) -> Self {
        Self { output }
    }

    /// Appends bytes unchanged.
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
    }

    /// Writes an 8-bit signed integer.
    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes an 8-bit unsigned integer.
    pub fn write_u8(&mut self, value: u8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 16-bit signed integer.
    pub fn write_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 16-bit unsigned integer.
    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 32-bit signed integer.
    pub fn write_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 32-bit unsigned integer.
    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 64-bit signed integer.
    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 64-bit unsigned integer.
    pub fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes the string bytes followed by a NUL byte.
    pub fn write_string(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
        self.write_u8(0);
    }

    /// Writes the string as UTF-16LE code units followed by a NUL code unit.
    pub fn write_string_utf16(&mut self, value: &str) {
        for unit in value.encode_utf16() {
            self.write_bytes(&unit.to_le_bytes());
        }
        self.write_u16(0);
    }
}

/// Defines how a shellcode parameter block is aligned and written.
pub trait Parameters {
    /// Required alignment of the whole parameter block within the payload.
    ///
    /// This value must be a nonzero power of two.
    /// It does not add per-field padding.
    const ALIGNMENT: usize;

    /// Appends the parameter block.
    fn encode(&self, writer: &mut ParameterWriter);
}

/// Resolved parameter passed to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parameter {
    /// Offset relative to the allocation holding the payload.
    Offset(u64),

    /// Exact value passed to the shellcode.
    Value(u64),
}

/// Exact value to pass to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterValue(pub u64);

/// Defines how a shellcode parameter is stored in the payload.
pub trait ParameterSource {
    /// Adds any required parameter data and returns the resolved parameter.
    fn resolve(self, payload: &mut Vec<u8>) -> Parameter;
}

impl<ParametersType> ParameterSource for &ParametersType
where
    ParametersType: Parameters,
{
    fn resolve(self, payload: &mut Vec<u8>) -> Parameter {
        debug_assert!(
            ParametersType::ALIGNMENT.is_power_of_two(),
            "shellcode parameter alignment must be a nonzero power of two"
        );

        // Align the parameter block within the payload.
        let parameter_offset = payload.len().next_multiple_of(ParametersType::ALIGNMENT);
        payload.resize(parameter_offset, 0);

        // Append the encoded parameters at the aligned offset.
        let mut writer = ParameterWriter::new(payload);
        self.encode(&mut writer);

        Parameter::Offset(parameter_offset as u64)
    }
}

impl ParameterSource for ParameterValue {
    fn resolve(self, _payload: &mut Vec<u8>) -> Parameter {
        Parameter::Value(self.0)
    }
}

/// Encodes a standalone parameter block for test assertions.
#[cfg(test)]
pub fn encode_parameters(parameters: &impl Parameters) -> Vec<u8> {
    let mut output = Vec::new();
    parameters.encode(&mut ParameterWriter::new(&mut output));
    output
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

    impl Parameters for FourByteParameters {
        const ALIGNMENT: usize = 4;

        fn encode(&self, writer: &mut ParameterWriter<'_>) {
            writer.write_bytes(&[0x11, 0x22]);
        }
    }

    #[test]
    fn parameter_block_alignment_does_not_pad_stored_bytes() {
        const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];
        let mut bytes = SHELLCODE.to_vec();

        let parameter = (&FourByteParameters).resolve(&mut bytes);

        assert_eq!(parameter, Parameter::Offset(4));
        assert_eq!(&bytes[..SHELLCODE.len()], SHELLCODE);
        assert_eq!(bytes[SHELLCODE.len()], 0);
        assert_eq!(&bytes[4..], &[0x11, 0x22]);
        assert_eq!(bytes.len(), 6);
    }

    #[test]
    fn already_aligned_parameter_offset_is_unchanged() {
        let mut bytes = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let parameter = (&FourByteParameters).resolve(&mut bytes);

        assert_eq!(parameter, Parameter::Offset(4));
    }

    struct ZeroAlignedParameters;

    impl Parameters for ZeroAlignedParameters {
        const ALIGNMENT: usize = 0;

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
    }

    struct ThreeByteAlignedParameters;

    impl Parameters for ThreeByteAlignedParameters {
        const ALIGNMENT: usize = 3;

        fn encode(&self, _writer: &mut ParameterWriter<'_>) {}
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_zero_parameter_alignment() {
        (&ZeroAlignedParameters).resolve(&mut vec![0xaa]);
    }

    #[test]
    #[should_panic(expected = "shellcode parameter alignment must be a nonzero power of two")]
    fn rejects_non_power_of_two_parameter_alignment() {
        (&ThreeByteAlignedParameters).resolve(&mut vec![0xaa]);
    }
}
