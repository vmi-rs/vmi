/// The address space type in a WoW64 process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsWow64Kind {
    /// Native address space.
    Native = 0,

    /// x86 (32-bit) address space under WoW64.
    X86 = 1,
    // Arm32 = 2,
    // Amd64 = 3,
    // ChpeX86 = 4,
    // VsmEnclave = 5,
}

/// Per-thread data for the CPU simulator.
pub const WOW64_TLS_CPURESERVED: usize = 1;

/// List of memory allocated in thunk call.
pub const WOW64_TLS_TEMPLIST: usize = 3;

/// Used by win32k callbacks.
pub const WOW64_TLS_USERCALLBACKDATA: usize = 5;

/// List of outstanding usermode APCs.
pub const WOW64_TLS_APCLIST: usize = 7;

/// Used to enable/disable the filesystem redirector.
pub const WOW64_TLS_FILESYSREDIR: usize = 8;

/// Wow64Info address (structure shared between 32-bit and 64-bit code inside Wow64).
pub const WOW64_TLS_WOW64INFO: usize = 10;
