use crate::recipe::{ParameterWriter, ShellcodeParameters};

/// Host representation of the msgbox shellcode's sequential parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgboxParameters {
    /// Window title passed to `MessageBoxA`.
    title: String,

    /// Message text passed to `MessageBoxA`.
    text: String,
}

impl MsgboxParameters {
    /// Creates a message box request.
    pub fn new(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            text: text.into(),
        }
    }
}

impl ShellcodeParameters for MsgboxParameters {
    const ALIGNMENT: usize = 1;

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_string(&self.title);
        writer.write_string(&self.text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::encode_parameters;

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
