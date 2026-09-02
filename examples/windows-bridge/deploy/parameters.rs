use crate::recipe::{ParameterWriter, ShellcodeParameters};

bitflags::bitflags! {
    /// Operation and optional-field flags consumed by the deploy shellcode.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct ParameterFlags: u32 {
        /// Enables archive extraction after a download.
        const EXTRACT = 1 << 0;

        /// Enables executable launch.
        const EXECUTE = 1 << 1;

        /// Enables file download.
        const DOWNLOAD = 1 << 2;

        /// Marks an encoded execution argument string as present.
        const ARGUMENTS = 1 << 8;

        /// Marks an encoded execution working directory as present.
        const WORKING_DIRECTORY = 1 << 9;

        /// Marks an encoded execution display value as present.
        const SHOW_WINDOW = 1 << 10;
    }
}

/// Marks a builder without a download operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadDisabled;

/// Holds a download URL until its required destination path is supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadNeedsPath {
    /// URL passed to `URLDownloadToFileW`.
    url: String,
}

/// Holds a complete download operation and its optional extraction stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadEnabled {
    /// URL passed to `URLDownloadToFileW`.
    url: String,

    /// Guest destination path, including optional environment variables.
    path: String,

    /// Optional extraction directory.
    extraction_directory: Option<String>,
}

/// Marks a builder without an execution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionDisabled;

/// Holds a complete execution operation and its optional fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnabled {
    /// Guest executable path, including optional environment variables.
    path: String,

    /// Optional command-line arguments. An empty string remains present.
    arguments: Option<String>,

    /// Optional guest working directory.
    working_directory: Option<String>,

    /// Optional Windows `SW_*` display value.
    show_window: Option<i32>,
}

/// Host representation of the deploy shellcode's sequential parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployParameters {
    /// Optional complete download operation.
    download: Option<DownloadEnabled>,

    /// Optional complete execution operation.
    execution: Option<ExecutionEnabled>,
}

impl DeployParameters {
    /// Starts a no-op builder with download and execution disabled.
    pub fn builder() -> DeployParametersBuilder {
        DeployParametersBuilder {
            download: DownloadDisabled,
            execution: ExecutionDisabled,
        }
    }

    /// Computes the operation and optional-field flags.
    fn flags(&self) -> ParameterFlags {
        let mut flags = ParameterFlags::empty();

        if let Some(download) = &self.download {
            flags |= ParameterFlags::DOWNLOAD;

            if download.extraction_directory.is_some() {
                flags |= ParameterFlags::EXTRACT;
            }
        }

        if let Some(execution) = &self.execution {
            flags |= ParameterFlags::EXECUTE;

            if execution.arguments.is_some() {
                flags |= ParameterFlags::ARGUMENTS;
            }

            if execution.working_directory.is_some() {
                flags |= ParameterFlags::WORKING_DIRECTORY;
            }

            if execution.show_window.is_some() {
                flags |= ParameterFlags::SHOW_WINDOW;
            }
        }

        flags
    }

    /// Erases completed builder states into serializable parameters.
    fn from_states(download: Option<DownloadEnabled>, execution: Option<ExecutionEnabled>) -> Self {
        Self {
            download,
            execution,
        }
    }
}

impl ShellcodeParameters for DeployParameters {
    const ALIGNMENT: usize = align_of::<u32>();

    fn encode(&self, writer: &mut ParameterWriter) {
        writer.write_u32(self.flags().bits());

        if let Some(download) = &self.download {
            writer.write_string_utf16(&download.url);
            writer.write_string_utf16(&download.path);

            if let Some(extraction_directory) = &download.extraction_directory {
                writer.write_string_utf16(extraction_directory);
            }
        }

        if let Some(execution) = &self.execution {
            writer.write_string_utf16(&execution.path);

            if let Some(arguments) = &execution.arguments {
                writer.write_string_utf16(arguments);
            }

            if let Some(working_directory) = &execution.working_directory {
                writer.write_string_utf16(working_directory);
            }

            if let Some(show_window) = execution.show_window {
                writer.write_i32(show_window);
            }
        }
    }
}

/// Builds one deploy request while tracking enabled operations in its type.
///
/// Callers must supply strings accepted by the guest APIs. Values are not validated.
/// Download setters are unavailable after [`execute`](Self::execute), so an
/// enabled download must be completed before execution is configured.
#[derive(Debug)]
#[must_use]
pub struct DeployParametersBuilder<Download = DownloadDisabled, Execution = ExecutionDisabled> {
    /// Download operation state.
    download: Download,

    /// Execution operation state.
    execution: Execution,
}

impl DeployParametersBuilder<DownloadDisabled, ExecutionDisabled> {
    /// Enables download and supplies its required URL.
    pub fn download(
        self,
        url: impl Into<String>,
    ) -> DeployParametersBuilder<DownloadNeedsPath, ExecutionDisabled> {
        DeployParametersBuilder {
            download: DownloadNeedsPath { url: url.into() },
            execution: self.execution,
        }
    }
}

impl DeployParametersBuilder<DownloadNeedsPath, ExecutionDisabled> {
    /// Supplies the required destination path for an enabled download.
    pub fn download_path(
        self,
        path: impl Into<String>,
    ) -> DeployParametersBuilder<DownloadEnabled, ExecutionDisabled> {
        DeployParametersBuilder {
            download: DownloadEnabled {
                url: self.download.url,
                path: path.into(),
                extraction_directory: None,
            },
            execution: self.execution,
        }
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionDisabled> {
    /// Enables extraction into the supplied guest directory.
    #[expect(unused)]
    pub fn extraction_directory(self, extraction_directory: impl Into<String>) -> Self {
        self.maybe_extraction_directory(Some(extraction_directory))
    }

    /// Supplies an optional extraction directory.
    pub fn maybe_extraction_directory(
        self,
        extraction_directory: Option<impl Into<String>>,
    ) -> Self {
        Self {
            download: DownloadEnabled {
                extraction_directory: extraction_directory.map(Into::into),
                ..self.download
            },
            execution: self.execution,
        }
    }
}

impl DeployParametersBuilder<DownloadDisabled, ExecutionDisabled> {
    /// Enables execution without a preceding download.
    pub fn execute(
        self,
        path: impl Into<String>,
    ) -> DeployParametersBuilder<DownloadDisabled, ExecutionEnabled> {
        DeployParametersBuilder {
            download: self.download,
            execution: ExecutionEnabled {
                path: path.into(),
                arguments: None,
                working_directory: None,
                show_window: None,
            },
        }
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionDisabled> {
    /// Enables execution after a complete download operation.
    pub fn execute(
        self,
        path: impl Into<String>,
    ) -> DeployParametersBuilder<DownloadEnabled, ExecutionEnabled> {
        DeployParametersBuilder {
            download: self.download,
            execution: ExecutionEnabled {
                path: path.into(),
                arguments: None,
                working_directory: None,
                show_window: None,
            },
        }
    }
}

impl<Download> DeployParametersBuilder<Download, ExecutionEnabled> {
    /// Supplies a present argument slot. An empty string remains meaningful.
    #[expect(unused)]
    pub fn arguments(self, arguments: impl Into<String>) -> Self {
        self.maybe_arguments(Some(arguments))
    }

    /// Supplies an optional argument slot. A present empty string remains meaningful.
    pub fn maybe_arguments(self, arguments: Option<impl Into<String>>) -> Self {
        Self {
            download: self.download,
            execution: ExecutionEnabled {
                arguments: arguments.map(Into::into),
                ..self.execution
            },
        }
    }

    /// Supplies a present guest working directory.
    #[expect(unused)]
    pub fn working_directory(self, working_directory: impl Into<String>) -> Self {
        self.maybe_working_directory(Some(working_directory))
    }

    /// Supplies an optional guest working directory.
    pub fn maybe_working_directory(self, working_directory: Option<impl Into<String>>) -> Self {
        Self {
            download: self.download,
            execution: ExecutionEnabled {
                working_directory: working_directory.map(Into::into),
                ..self.execution
            },
        }
    }

    /// Supplies an explicit Windows `SW_*` display value.
    #[expect(unused)]
    pub fn show_window(self, show_window: i32) -> Self {
        self.maybe_show_window(Some(show_window))
    }

    /// Supplies an optional Windows `SW_*` display value.
    pub fn maybe_show_window(self, show_window: Option<i32>) -> Self {
        Self {
            download: self.download,
            execution: ExecutionEnabled {
                show_window,
                ..self.execution
            },
        }
    }
}

impl DeployParametersBuilder<DownloadDisabled, ExecutionDisabled> {
    /// Finishes a no-op request.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(None, None)
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionDisabled> {
    /// Finishes a request containing only download and optional extraction.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(Some(self.download), None)
    }
}

impl DeployParametersBuilder<DownloadDisabled, ExecutionEnabled> {
    /// Finishes a request containing only execution.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(None, Some(self.execution))
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionEnabled> {
    /// Finishes a request containing download and execution operations.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(Some(self.download), Some(self.execution))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::encode_parameters;

    #[test]
    fn parameter_block_is_u32_aligned() {
        assert_eq!(
            <DeployParameters as ShellcodeParameters>::ALIGNMENT,
            align_of::<u32>()
        );
    }

    #[test]
    fn serializes_no_operation_request() {
        let bytes = encode_parameters(&DeployParameters::builder().build());

        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn serializes_all_conditional_slots_in_cursor_order() {
        let parameters = DeployParameters::builder()
            .download("u")
            .download_path("d")
            .extraction_directory("x")
            .execute("e")
            .arguments("")
            .working_directory("w")
            .show_window(5)
            .build();

        let bytes = encode_parameters(&parameters);

        assert_eq!(
            bytes,
            [
                0x07, 0x07, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
                b'x', 0, 0, 0, // extraction directory
                b'e', 0, 0, 0, // executable path
                0, 0, // present empty arguments
                b'w', 0, 0, 0, // working directory
                5, 0, 0, 0, // show window
            ]
        );
    }

    #[test]
    fn maybe_setters_encode_only_present_values() {
        let parameters = DeployParameters::builder()
            .download("u")
            .download_path("d")
            .maybe_extraction_directory(Some("x"))
            .execute("e")
            .maybe_arguments(None::<&str>)
            .maybe_working_directory(Some("w"))
            .maybe_show_window(None)
            .build();
        let bytes = encode_parameters(&parameters);

        assert_eq!(
            bytes,
            [
                0x07, 0x02, 0x00, 0x00, // flags
                b'u', 0, 0, 0, // URL
                b'd', 0, 0, 0, // download path
                b'x', 0, 0, 0, // extraction directory
                b'e', 0, 0, 0, // executable path
                b'w', 0, 0, 0, // working directory
            ]
        );
    }

    #[test]
    fn builds_execute_only_parameters() {
        let parameters = DeployParameters::builder().execute("program.exe").build();
        let bytes = encode_parameters(&parameters);

        assert_eq!(&bytes[..4], &ParameterFlags::EXECUTE.bits().to_le_bytes());
    }
}
