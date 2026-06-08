//! Terminal coloring for the trace output.
//!
//! Colors are 24-bit ANSI (`38;2;R;G;B`) and are emitted only when stdout is a
//! terminal and `NO_COLOR` is unset. When disabled, every paint method returns
//! the text unchanged, so the same formatting code drives both a TTY and a
//! redirected file.

use std::io::IsTerminal as _;

/// Returns true when stdout is a terminal and `NO_COLOR` is unset.
pub fn stdout_supports_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// 24-bit color scheme for one trace line.
#[derive(Clone, Copy)]
pub struct Palette {
    /// Whether to emit escape sequences at all.
    enabled: bool,
}

impl Palette {
    /// Creates a palette that emits color only when `enabled`.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Wraps `text` in `code` and a reset, or returns it bare when disabled.
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        }
        else {
            text.to_string()
        }
    }

    /// Bold white. Used for the leading timestamp.
    pub fn timestamp(&self, text: &str) -> String {
        self.paint("1;38;2;255;255;255", text)
    }

    /// Light blue. Used for the module name.
    pub fn module(&self, text: &str) -> String {
        self.paint("38;2;165;214;255", text)
    }

    /// Light purple. Used for the function name.
    pub fn function(&self, text: &str) -> String {
        self.paint("38;2;210;168;255", text)
    }

    /// Orange. Used for argument names.
    pub fn arg_name(&self, text: &str) -> String {
        self.paint("38;2;255;166;87", text)
    }

    /// Plain white. Used for the `=` between an argument name and its value.
    pub fn equals(&self) -> String {
        self.paint("38;2;255;255;255", "=")
    }

    /// Green. Used for numeric, pointer, and boolean argument values.
    pub fn number(&self, text: &str) -> String {
        self.paint("38;2;86;211;100", text)
    }

    /// Light blue. Used for dereferenced string argument values.
    pub fn string(&self, text: &str) -> String {
        self.paint("38;2;165;214;255", text)
    }

    /// Bold red. Used for a null pointer argument.
    pub fn null(&self) -> String {
        self.paint("1;38;2;255;123;114", "NULL")
    }
}
