#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
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

    /// Writes a 8-bit signed integer.
    pub fn write_i8(&mut self, value: i8) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a 8-bit unsigned integer.
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
pub trait ShellcodeParameters {
    /// Required alignment of the parameter block within the payload.
    ///
    /// This value must be a nonzero power of two.
    const ALIGNMENT: usize;

    /// Appends the parameter block.
    fn encode(&self, writer: &mut ParameterWriter);
}

/// Resolved parameter passed to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeParameter {
    /// Offset relative to the shellcode allocation.
    Offset(u64),

    /// Exact value passed to the shellcode.
    Value(u64),
}

/// Exact value to pass to a shellcode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellcodeParameterValue(pub u64);

/// Defines how a shellcode parameter is stored in the payload.
pub trait ShellcodeParameterSource {
    /// Adds any required parameter data and returns the resolved parameter.
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

#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
/// Prepared shellcode and parameter data.
#[derive(Debug)]
pub struct ShellcodePayload {
    /// Prepared payload bytes.
    pub bytes: Vec<u8>,

    /// Prepared shellcode parameter.
    pub parameter: ShellcodeParameter,
}

#[cfg(all(feature = "arch-amd64", feature = "os-windows"))]
impl ShellcodePayload {
    /// Creates a payload from the given shellcode and parameter.
    pub fn new(shellcode: impl AsRef<[u8]>, parameter: impl ShellcodeParameterSource) -> Self {
        let mut bytes = shellcode.as_ref().to_vec();
        let parameter = parameter.resolve(&mut bytes);

        Self { bytes, parameter }
    }

    /// Returns the parameter value for the given payload allocation base.
    pub fn parameter_value(&self, allocation_base: Va) -> u64 {
        match self.parameter {
            ShellcodeParameter::Offset(offset) => allocation_base.0 + offset,
            ShellcodeParameter::Value(value) => value,
        }
    }
}
