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
