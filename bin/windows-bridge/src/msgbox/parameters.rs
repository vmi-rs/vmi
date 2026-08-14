/// Host representation of the msgbox shellcode's sequential parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MsgboxParameters {
    /// Window title passed to `MessageBoxA`.
    title: String,

    /// Message text passed to `MessageBoxA`.
    text: String,
}

impl MsgboxParameters {
    /// Creates a message box request.
    pub(crate) fn new(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            text: text.into(),
        }
    }

    /// Serializes the byte strings consumed by the shellcode.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.append_to(&mut bytes);
        bytes
    }

    /// Appends the title and text as consecutive NUL-terminated byte strings.
    pub(super) fn append_to(&self, bytes: &mut Vec<u8>) {
        append_string(bytes, &self.title);
        append_string(bytes, &self.text);
    }
}

/// Appends one NUL-terminated byte string.
fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_title_before_text() {
        let parameters = MsgboxParameters::new("VMI", "Hello");

        assert_eq!(parameters.serialize(), b"VMI\0Hello\0");
    }

    #[test]
    fn preserves_empty_fields() {
        let parameters = MsgboxParameters::new("", "");

        assert_eq!(parameters.serialize(), b"\0\0");
    }
}
