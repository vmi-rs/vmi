use vmi::utils::shellcode::{ParameterWriter, Parameters};

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

impl Parameters for MsgboxParameters {
    /// Uses byte alignment because the shellcode reads both strings as `char`
    /// arrays, which do not require padding.
    const ALIGNMENT: usize = 1;

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_string(&self.title);
        writer.write_string(&self.text);
    }
}
