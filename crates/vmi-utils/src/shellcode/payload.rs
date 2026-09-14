use vmi_core::Va;

use super::parameters::{Parameter, ParameterSource};

/// Payload containing shellcode and any encoded parameters.
#[derive(Debug)]
pub struct Payload {
    /// Payload bytes.
    pub bytes: Vec<u8>,

    /// Entry-point parameter resolved during payload preparation.
    pub parameter: Parameter,
}

impl Payload {
    /// Creates a payload from shellcode and a parameter.
    pub fn new(shellcode: impl AsRef<[u8]>, parameter: impl ParameterSource) -> Self {
        let mut bytes = shellcode.as_ref().to_vec();
        let parameter = parameter.resolve(&mut bytes);

        Self { bytes, parameter }
    }

    /// Returns the parameter for the given allocation base.
    pub fn parameter_value(&self, allocation_base: Va) -> u64 {
        match self.parameter {
            Parameter::Offset(offset) => allocation_base.0 + offset,
            Parameter::Value(value) => value,
        }
    }
}
