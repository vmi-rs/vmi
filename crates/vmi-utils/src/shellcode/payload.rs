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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shellcode::{ParameterValue, ParameterWriter, Parameters};

    struct FourByteParameters;

    impl Parameters for FourByteParameters {
        const ALIGNMENT: usize = 4;

        fn encode(&self, writer: &mut ParameterWriter<'_>) {
            writer.write_bytes(&[0x11, 0x22]);
        }
    }

    #[test]
    fn direct_parameter_value_does_not_append_data() {
        const SHELLCODE: &[u8] = &[0xaa, 0xbb, 0xcc];
        const PARAMETER: u64 = 0x1122_3344_5566_7788;

        let payload = Payload::new(SHELLCODE, ParameterValue(PARAMETER));

        assert_eq!(payload.parameter, Parameter::Value(PARAMETER));
        assert_eq!(payload.bytes, SHELLCODE);
        assert_eq!(payload.parameter_value(Va(0x1000)), PARAMETER);
    }

    #[test]
    fn payload_offset_resolves_against_each_allocation() {
        let payload = Payload::new([0xaa, 0xbb, 0xcc], &FourByteParameters);

        assert_eq!(payload.parameter_value(Va(0x1000)), 0x1004);
        assert_eq!(payload.parameter_value(Va(0x2000)), 0x2004);
    }
}
