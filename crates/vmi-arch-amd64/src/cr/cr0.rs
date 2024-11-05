/// `CR0` control register.
///
/// Manages the processor's operating mode and system states. Controls protected
/// mode, paging, floating point unit, and various CPU features.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Cr0(pub u64);

impl Cr0 {
    /// Checks if the CR0.PE flag is set.
    ///
    /// Enables protected mode when set; enables real-address mode when
    /// clear. This flag does not enable paging directly. It only enables
    /// segment-level protection. To enable paging, both the PE and PG flags
    /// must be set.
    pub fn protection_enable(self) -> bool {
        self.0 & 1 != 0
    }

    /// Checks if the CR0.MP flag is set.
    ///
    /// Controls the interaction of the WAIT (or FWAIT) instruction with
    /// Checks if the the TS flag flag is set. CR0). If the MP flag is set, a
    /// WAIT instruction generates a device-not-available exception (#NM) if
    /// the TS flag is also set. If the MP flag is clear, the WAIT instruction
    /// ignores the setting of the TS flag.
    pub fn monitor_coprocessor(self) -> bool {
        self.0 >> 1 & 1 != 0
    }

    /// Checks if the CR0.EM flag is set.
    ///
    /// Indicates that the processor does not have an internal or external x87
    /// FPU when set; indicates an x87 FPU is present when clear. This flag
    /// also affects the execution of MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// instructions.
    pub fn emulation(self) -> bool {
        self.0 >> 2 & 1 != 0
    }

    /// Checks if the CR0.TS flag is set.
    ///
    /// Allows the saving of the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// context on a task switch to be delayed until an x87
    /// FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction is actually executed by
    /// the new task. The processor sets this flag on every task switch and
    /// tests it when executing x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// instructions.
    pub fn task_switched(self) -> bool {
        self.0 >> 3 & 1 != 0
    }

    /// Checks if the CR0.ET flag is set.
    ///
    /// Reserved in the Pentium 4, Intel Xeon, P6 family, and Pentium
    /// processors. In the Pentium 4, Intel Xeon, and P6 family processors,
    /// this flag is hardcoded to 1. In the Intel386 and Intel486
    /// processors, this flag indicates support of Intel 387 DX math coprocessor
    /// instructions when set.
    pub fn extension_type(self) -> bool {
        self.0 >> 4 & 1 != 0
    }

    /// Checks if the CR0.NE flag is set.
    ///
    /// Enables the native (internal) mechanism for reporting x87 FPU errors
    /// when set; enables the PC-style x87 FPU error reporting mechanism when
    /// clear.
    pub fn numeric_error(self) -> bool {
        self.0 >> 5 & 1 != 0
    }

    /// Checks if the CR0.WP flag is set.
    ///
    /// When set, inhibits supervisor-level procedures from writing into
    /// readonly pages; when clear, allows supervisor-level procedures to
    /// write into read-only pages (regardless of the U/S bit setting). This
    /// flag facilitates implementation of the copy-onwrite
    /// method of creating a new process (forking) used by operating systems
    /// such as UNIX.
    pub fn write_protect(self) -> bool {
        self.0 >> 16 & 1 != 0
    }

    /// Checks if the CR0.AM flag is set.
    ///
    /// Enables automatic alignment checking when set; disables alignment
    /// checking when clear. Alignment checking is performed only when the AM
    /// flag is set, the AC flag in the EFLAGS register is set, CPL is 3,
    /// and the processor is operating in either protected or virtual-8086 mode.
    pub fn alignment_mask(self) -> bool {
        self.0 >> 18 & 1 != 0
    }

    /// Checks if the CR0.NW flag is set.
    ///
    /// When the NW and CD flags are clear, write-back or write-through is
    /// enabled for writes that hit the cache and invalidation cycles are
    /// enabled.
    pub fn not_write_through(self) -> bool {
        self.0 >> 29 & 1 != 0
    }

    /// Checks if the CR0.CD flag is set.
    ///
    /// When the CD and NW flags are clear, caching of memory locations for
    /// the whole of physical memory in the processor’s internal (and external)
    /// caches is enabled. When the CD flag is set, caching is restricted.
    pub fn cache_disable(self) -> bool {
        self.0 >> 30 & 1 != 0
    }

    /// Checks if the CR0.PG flag is set.
    ///
    /// Enables paging when set; disables paging when clear. When paging is
    /// disabled, all linear addresses are treated as physical addresses. The PG
    /// flag has no effect if the PE flag (bit 0 of register CR0) is not
    /// also set; setting the PG flag when the PE flag is clear causes a
    /// general-protection exception (#GP).
    ///
    /// On Intel 64 processors, enabling and disabling IA-32e mode operation
    /// also requires modifying CR0.PG.
    pub fn paging(self) -> bool {
        self.0 >> 31 & 1 != 0
    }
}

impl std::fmt::Debug for Cr0 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Cr0")
            .field("protection_enable", &self.protection_enable())
            .field("monitor_coprocessor", &self.monitor_coprocessor())
            .field("emulation", &self.emulation())
            .field("task_switched", &self.task_switched())
            .field("extension_type", &self.extension_type())
            .field("numeric_error", &self.numeric_error())
            .field("write_protect", &self.write_protect())
            .field("alignment_mask", &self.alignment_mask())
            .field("not_write_through", &self.not_write_through())
            .field("cache_disable", &self.cache_disable())
            .field("paging", &self.paging())
            .finish()
    }
}

impl From<u64> for Cr0 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Cr0> for u64 {
    fn from(value: Cr0) -> Self {
        value.0
    }
}
