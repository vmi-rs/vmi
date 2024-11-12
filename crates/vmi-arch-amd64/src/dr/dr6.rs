/// `DR6` debug status register.
///
/// Reports debug conditions that were sampled at the time the last debug
/// exception was generated. Updates to this register only occur when an
/// exception is generated.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr6(pub u64);

impl Dr6 {
    /// B0 through B3 (breakpoint condition detected) flags (bits 0 through 3).
    ///
    /// Indicates (when set) that its
    /// associated breakpoint condition was met when a debug exception was
    /// generated. These flags are set if the condition described for each
    /// breakpoint by the LENn, and R/Wn flags in debug control register DR7 is
    /// true. They may or may not be set if the breakpoint is not enabled by
    /// the Ln or the Gn flags in register DR7. Therefore on a #DB, a debug
    /// handler should check only those B0-B3 bits which correspond to an
    /// enabled breakpoint.
    pub fn breakpoint_condition(self) -> u8 {
        (self.0 & 0b1111) as _
    }

    /// BLD (bus-lock detected) flag (bit 11).
    /// Indicates (when clear) that the debug exception was triggered by
    /// the assertion of a bus lock when CPL > 0 and OS bus-lock detection was
    /// enabled. Other debug exceptions do not modify this bit. To avoid
    /// confusion in identifying debug exceptions, software debugexception
    /// handlers should set bit 11 to 1 before returning. (Software that never
    /// enables OS bus-lock detection need not do this as DR6\[11\] = 1
    /// following reset.) This bit is always 1 if the processor does not support
    /// OS buslock detection
    pub fn bus_lock_detected(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }

    /// BD (debug register access detected) flag (bit 13).
    ///
    /// Indicates that the next instruction in the instruction
    /// stream accesses one of the debug registers (DR0 through DR7). This flag
    /// is enabled when the GD (general detect) flag in debug control
    /// register DR7 is set.
    pub fn debug_register_access_detected(self) -> bool {
        (self.0 >> 13) & 1 != 0
    }

    /// BS (single step) flag (bit 14).
    ///
    /// Indicates (when set) that the debug exception was triggered by the
    /// singlestep execution mode (enabled with the TF flag in the EFLAGS
    /// register). The single-step mode is the highestpriority
    /// debug exception. When the BS flag is set, any of the other debug status
    /// bits also may be set.
    pub fn single_step(self) -> bool {
        (self.0 >> 14) & 1 != 0
    }

    /// BT (task switch) flag (bit 15).
    ///
    /// Indicates (when set) that the debug exception was triggered by the
    /// singlestep execution mode (enabled with the TF flag in the EFLAGS
    /// register). The single-step mode is the highestpriority
    /// debug exception. When the BS flag is set, any of the other debug status
    /// bits also may be set.
    pub fn task_switch(self) -> bool {
        (self.0 >> 15) & 1 != 0
    }

    /// RTM (restricted transactional memory) flag (bit 16).
    ///
    /// Indicates (when clear) that a debug exception
    /// (#DB) or breakpoint exception (#BP) occurred inside an RTM region while
    /// advanced debugging of RTM transactional regions was enabled. This
    /// bit is set for any other debug exception (including all those that
    /// occur when advanced debugging of RTM transactional regions is not
    /// enabled). This bit is always 1 if the processor does not support
    /// RTM.
    pub fn restricted_transactional_memory(self) -> bool {
        (self.0 >> 16) & 1 != 0
    }
}

impl std::fmt::Debug for Dr6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Dr6")
            .field("breakpoint_condition", &self.breakpoint_condition())
            .field("bus_lock_detected", &self.bus_lock_detected())
            .field(
                "debug_register_access_detected",
                &self.debug_register_access_detected(),
            )
            .field("single_step", &self.single_step())
            .field("task_switch", &self.task_switch())
            .field(
                "restricted_transactional_memory",
                &self.restricted_transactional_memory(),
            )
            .finish()
    }
}

impl From<u64> for Dr6 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr6> for u64 {
    fn from(value: Dr6) -> Self {
        value.0
    }
}
