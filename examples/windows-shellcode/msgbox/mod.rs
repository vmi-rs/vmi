//! `msgbox` shellcode.
//!
//! Handles displaying a message box in a Windows guest process.

mod bridge;
mod command;
mod parameters;
mod recipe;

pub use self::command::{MsgboxArguments, run};
