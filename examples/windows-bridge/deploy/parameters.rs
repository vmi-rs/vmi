use vmi::utils::shellcode::{ParameterWriter, Parameters};

bitflags::bitflags! {
    /// Flags for the `deploy` shellcode.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct ParameterFlags: u32 {
        /// Enables file download.
        const DOWNLOAD = 0x0001;

        /// Enables execution of the configured executable.
        const EXECUTE = 0x0002;

        /// Enables extraction of the downloaded archive.
        ///
        /// Requires `DOWNLOAD` to be set.
        const EXTRACT = 0x0100;

        /// Indicates that a command-line argument string is present.
        ///
        /// Requires `EXECUTE` to be set.
        const ARGUMENTS = 0x1000;

        /// Indicates that an execution working-directory string is present.
        ///
        /// Requires `EXECUTE` to be set.
        const WORKING_DIRECTORY = 0x2000;

        /// Indicates that a Windows SW_* show-window value is present.
        ///
        /// Requires `EXECUTE` to be set.
        const SHOW_WINDOW = 0x4000;
    }
}

/// Builder state without a download operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadDisabled;

/// Builder state awaiting the required destination path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadNeedsPath {
    /// URL passed to `URLDownloadToFileW`.
    url: String,
}

/// Builder state with a complete download configuration and optional
/// archive extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadEnabled {
    /// URL passed to `URLDownloadToFileW`.
    url: String,

    /// Guest destination path, including optional environment variables.
    path: String,

    /// Optional extraction directory.
    extraction_directory: Option<String>,
}

/// Builder state without an execution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionDisabled;

/// Builder state with a complete execution configuration.
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

/// Parameters for the `deploy` shellcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployParameters {
    /// Optional complete download operation.
    download: Option<DownloadEnabled>,

    /// Optional complete execution operation.
    execution: Option<ExecutionEnabled>,
}

impl DeployParameters {
    /// Creates a builder with download and execution disabled.
    pub fn builder() -> DeployParametersBuilder {
        DeployParametersBuilder {
            download: DownloadDisabled,
            execution: ExecutionDisabled,
        }
    }

    /// Returns the operation and optional-field flags.
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

    /// Creates serializable parameters from completed builder states.
    fn from_states(download: Option<DownloadEnabled>, execution: Option<ExecutionEnabled>) -> Self {
        Self {
            download,
            execution,
        }
    }
}

impl Parameters for DeployParameters {
    /// Uses `u32` alignment because the operation flags (which are u32)
    /// are encoded first.
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

/// Builds `deploy` parameters while tracking enabled operations in its type.
///
/// Callers must supply strings accepted by the guest APIs. Values are not
/// validated. Download setters are unavailable after [`execute`](Self::execute),
/// so an enabled download must be completed before execution is configured.
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
    /// Sets the guest extraction directory.
    #[allow(unused, reason = "exercised by tests only")]
    pub fn extraction_directory(self, extraction_directory: impl Into<String>) -> Self {
        self.maybe_extraction_directory(Some(extraction_directory))
    }

    /// Sets the optional guest extraction directory.
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
    /// Sets command-line arguments. An empty string remains present.
    #[allow(unused, reason = "exercised by tests only")]
    pub fn arguments(self, arguments: impl Into<String>) -> Self {
        self.maybe_arguments(Some(arguments))
    }

    /// Sets optional command-line arguments. A present empty string remains meaningful.
    pub fn maybe_arguments(self, arguments: Option<impl Into<String>>) -> Self {
        Self {
            download: self.download,
            execution: ExecutionEnabled {
                arguments: arguments.map(Into::into),
                ..self.execution
            },
        }
    }

    /// Sets the guest working directory.
    #[allow(unused, reason = "exercised by tests only")]
    pub fn working_directory(self, working_directory: impl Into<String>) -> Self {
        self.maybe_working_directory(Some(working_directory))
    }

    /// Sets the optional guest working directory.
    pub fn maybe_working_directory(self, working_directory: Option<impl Into<String>>) -> Self {
        Self {
            download: self.download,
            execution: ExecutionEnabled {
                working_directory: working_directory.map(Into::into),
                ..self.execution
            },
        }
    }

    /// Sets the Windows `SW_*` display value.
    #[allow(unused, reason = "exercised by tests only")]
    pub fn show_window(self, show_window: i32) -> Self {
        self.maybe_show_window(Some(show_window))
    }

    /// Sets the optional Windows `SW_*` display value.
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
    /// Builds `deploy` parameters with no operations.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(None, None)
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionDisabled> {
    /// Builds `deploy` parameters with download and optional extraction.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(Some(self.download), None)
    }
}

impl DeployParametersBuilder<DownloadDisabled, ExecutionEnabled> {
    /// Builds `deploy` parameters with execution.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(None, Some(self.execution))
    }
}

impl DeployParametersBuilder<DownloadEnabled, ExecutionEnabled> {
    /// Builds `deploy` parameters with download and execution.
    pub fn build(self) -> DeployParameters {
        DeployParameters::from_states(Some(self.download), Some(self.execution))
    }
}
