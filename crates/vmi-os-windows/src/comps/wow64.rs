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
