//! `kernel-file` shellcode.
//!
//! Handles creating a guest file from kernel mode.

mod bridge;
mod command;
mod parameters;
mod recipe;

pub use self::command::{KernelFileArguments, run};
