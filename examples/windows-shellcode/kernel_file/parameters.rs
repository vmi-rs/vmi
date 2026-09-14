use vmi::utils::shellcode::{ParameterWriter, ShellcodeParameters};

/// Parameters for the `kernel-file` shellcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFileParameters {
    /// Guest NT path passed to `ZwCreateFile`.
    nt_path: String,
}

impl KernelFileParameters {
    /// Creates parameters for the given guest path.
    ///
    /// DOS paths such as `C:\dir\file.txt` are prefixed with `\??\` for
    /// `ZwCreateFile`. Paths beginning with `\` are treated as NT paths and
    /// left unchanged.
    pub fn new(path: impl AsRef<str>) -> Self {
        let path = path.as_ref();

        let nt_path = if path.starts_with('\\') {
            path.to_string()
        }
        else {
            format!(r"\??\{path}")
        };

        Self { nt_path }
    }

    /// Returns the guest NT path.
    pub fn nt_path(&self) -> &str {
        &self.nt_path
    }
}

impl ShellcodeParameters for KernelFileParameters {
    /// Uses `u16` alignment because the path is encoded as UTF-16.
    ///
    /// AMD64 permits unaligned 16-bit accesses, but an alignment of 1 could
    /// place the string at an odd address and technically violate the C++
    /// alignment requirements for `wchar_t`.
    const ALIGNMENT: usize = align_of::<u16>();

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_string_utf16(&self.nt_path);
    }
}
