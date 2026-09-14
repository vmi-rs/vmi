#![allow(dead_code, reason = "used by OS adapters")]

#[cfg(feature = "arch-amd64")]
mod amd64;

use vmi_core::{Architecture, Va};

/// Architecture-specific shellcode functionality.
pub trait ArchAdapter: Architecture {
    /// Thunk used to set up the arguments for the shellcode entry point.
    type Thunk: AsRef<[u8]>;

    /// Encodes a thunk that loads the kernel image base and parameter before
    /// entering the shellcode.
    fn encode_thunk(entry: Va, kernel_image_base: Va, parameter: u64) -> Self::Thunk;
}
