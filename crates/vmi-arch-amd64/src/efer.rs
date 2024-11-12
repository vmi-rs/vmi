/// Extended Feature Enable Register (EFER).
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct MsrEfer(pub u64);

impl MsrEfer {
    /// Checks if the SYSCALL enable (SCE) bit is set.
    ///
    /// When set, this bit enables the SYSCALL and SYSRET instructions.
    pub fn syscall_enable(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if Long Mode (aka IA-32e mode) is enabled (LME bit).
    ///
    /// When set, this bit enables 64-bit mode capability, but does not activate
    /// it. Long Mode becomes active when both this bit and the paging
    /// enable bit in CR0 are set.
    pub fn long_mode_enable(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// Checks if Long Mode (aka IA-32e mode) is active (LMA bit).
    ///
    /// This bit is read-only and indicates whether Long Mode is currently
    /// active. It is set by the processor when Long Mode is enabled and
    /// paging is turned on.
    pub fn long_mode_active(self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Checks if the Execute Disable (NX) feature is enabled.
    ///
    /// When set, this bit enables page-level execute protection.
    /// It allows marking of memory pages as non-executable, enhancing security
    /// by preventing the execution of code from data pages.
    pub fn execute_disable(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }
}

impl std::fmt::Debug for MsrEfer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("MsrEfer")
            .field("syscall_enable", &self.syscall_enable())
            .field("long_mode_enable", &self.long_mode_enable())
            .field("long_mode_active", &self.long_mode_active())
            .field("execute_disable", &self.execute_disable())
            .finish()
    }
}

impl From<u64> for MsrEfer {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<MsrEfer> for u64 {
    fn from(value: MsrEfer) -> Self {
        value.0
    }
}
