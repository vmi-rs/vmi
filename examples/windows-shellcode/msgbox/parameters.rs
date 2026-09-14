use vmi::utils::shellcode::{ParameterWriter, ShellcodeParameters};

/// Parameters for the `msgbox` shellcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgboxParameters {
    /// Window title passed to `MessageBoxA`.
    title: String,

    /// Message text passed to `MessageBoxA`.
    text: String,
}

impl MsgboxParameters {
    /// Creates parameters for the given title and message text.
    pub fn new(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            text: text.into(),
        }
    }
}

impl ShellcodeParameters for MsgboxParameters {
    /// Uses byte alignment because the shellcode reads both strings as `char`
    /// arrays, which do not require padding.
    const ALIGNMENT: usize = 1;

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_string(&self.title);
        writer.write_string(&self.text);
    }
}

/// Encodes msgbox parameters for test assertions.
#[cfg(test)]
fn encode_parameters(parameters: &impl ShellcodeParameters) -> Vec<u8> {
    let mut output = Vec::new();
    parameters.encode(&mut ParameterWriter::new(&mut output));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_block_is_byte_aligned() {
        assert_eq!(<MsgboxParameters as ShellcodeParameters>::ALIGNMENT, 1);
    }

    #[test]
    fn serializes_title_before_text() {
        let parameters = MsgboxParameters::new("VMI", "Hello");

        assert_eq!(encode_parameters(&parameters), b"VMI\0Hello\0");
    }

    #[test]
    fn preserves_empty_fields() {
        let parameters = MsgboxParameters::new("", "");

        assert_eq!(encode_parameters(&parameters), b"\0\0");
    }
}
