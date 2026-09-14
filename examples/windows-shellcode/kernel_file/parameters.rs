use vmi::utils::shellcode::{ParameterWriter, ShellcodeParameters};

/// Host representation of the kernel-file shellcode's parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFileParameters {
    /// NT path passed to `ZwCreateFile`.
    nt_path: String,
}

impl KernelFileParameters {
    /// Creates a kernel-file request for a guest path.
    ///
    /// A DOS path such as `C:\dir\file.txt` receives the `\??\` object-manager
    /// prefix that `ZwCreateFile` requires. A path that already starts with a
    /// backslash is treated as an NT path and passed through unchanged.
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

    /// Returns the NT path passed to the shellcode.
    pub fn nt_path(&self) -> &str {
        &self.nt_path
    }
}

impl ShellcodeParameters for KernelFileParameters {
    const ALIGNMENT: usize = align_of::<u16>();

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_string_utf16(&self.nt_path);
    }
}
