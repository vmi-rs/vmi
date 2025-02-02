/// `DR7` debug control register.
///
/// Enables or disables breakpoints and sets breakpoint conditions.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr7(pub u64);

/// Breakpoint condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointCondition {
    /// Break on instruction execution only.
    Execution,
    /// Break on data writes only.
    Write,
    /// Break on I/O reads or writes.
    Io,
    /// Break on data reads or writes but not instruction fetches.
    ReadWrite,
}

/// Breakpoint length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointLength {
    /// 1-byte length.
    Byte,
    /// 2-byte length.
    Word,
    /// 8-byte length.
    Quadword,
    /// 4-byte length.
    Dword,
}

impl Dr7 {
    /// L0 (local breakpoint enable) flag (bit 0).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for the current task. When a breakpoint condition is
    /// detected and this flag is set, a debug exception is generated. The
    /// processor automatically clears this flag on every task switch to
    /// avoid unwanted breakpoint conditions in the new task.
    pub fn local_breakpoint_0(self) -> bool {
        self.0 & 1 != 0
    }

    /// G0 (global breakpoint enable) flag (bit 1).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for all tasks. When a breakpoint condition is detected and
    /// this flag is set, a debug exception is generated. The processor does not
    /// clear this flag on a task switch, allowing a breakpoint to be enabled
    /// for all tasks.
    pub fn global_breakpoint_0(self) -> bool {
        (self.0 >> 1) & 1 != 0
    }

    /// L1 (local breakpoint enable) flag (bit 2).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for the current task. When a breakpoint condition is
    /// detected and this flag is set, a debug exception is generated. The
    /// processor automatically clears this flag on every task switch to
    /// avoid unwanted breakpoint conditions in the new task.
    pub fn local_breakpoint_1(self) -> bool {
        (self.0 >> 2) & 1 != 0
    }

    /// G1 (global breakpoint enable) flag (bit 3).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for all tasks. When a breakpoint condition is detected and
    /// this flag is set, a debug exception is generated. The processor does not
    /// clear this flag on a task switch, allowing a breakpoint to be enabled
    /// for all tasks.
    pub fn global_breakpoint_1(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }

    /// L2 (local breakpoint enable) flag (bit 4).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for the current task. When a breakpoint condition is
    /// detected and this flag is set, a debug exception is generated. The
    /// processor automatically clears this flag on every task switch to
    /// avoid unwanted breakpoint conditions in the new task.
    pub fn local_breakpoint_2(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }

    /// G2 (global breakpoint enable) flag (bit 5).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for all tasks. When a breakpoint condition is detected and
    /// this flag is set, a debug exception is generated. The processor does not
    /// clear this flag on a task switch, allowing a breakpoint to be enabled
    /// for all tasks.
    pub fn global_breakpoint_2(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }

    /// L3 (local breakpoint enable) flag (bit 6).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for the current task. When a breakpoint condition is
    /// detected and this flag is set, a debug exception is generated. The
    /// processor automatically clears this flag on every task switch to
    /// avoid unwanted breakpoint conditions in the new task.
    pub fn local_breakpoint_3(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }

    /// G3 (global breakpoint enable) flag (bit 7).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for all tasks. When a breakpoint condition is detected and
    /// this flag is set, a debug exception is generated. The processor does not
    /// clear this flag on a task switch, allowing a breakpoint to be enabled
    /// for all tasks.
    pub fn global_breakpoint_3(self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    /// LE (local exact breakpoint enable) flag (bit 8).
    ///
    /// When set, this flag cause the processor to detect the exact instruction
    /// that caused a data breakpoint condition.
    ///
    /// # Notes
    ///
    /// This feature is not supported in the P6 family processors, later IA-32
    /// processors, and Intel 64 processors.
    ///
    /// For backward and forward compatibility with other Intel processors, it
    /// is recommended that the LE and GE flags be set to 1 if exact
    /// breakpoints are required.
    pub fn local_exact_breakpoint_0(self) -> bool {
        (self.0 >> 8) & 1 != 0
    }

    /// GE (global exact breakpoint enable) flag (bit 9).
    ///
    /// When set, this flag cause the processor to detect the exact instruction
    /// that caused a data breakpoint condition.
    ///
    /// # Notes
    ///
    /// This feature is not supported in the P6 family processors, later IA-32
    /// processors, and Intel 64 processors.
    ///
    /// For backward and forward compatibility with other Intel processors, it
    /// is recommended that the LE and GE flags be set to 1 if exact
    /// breakpoints are required.
    pub fn global_exact_breakpoint_0(self) -> bool {
        (self.0 >> 9) & 1 != 0
    }

    /// RTM (restricted transactional memory) flag (bit 11).
    ///
    /// Enables (when set) advanced debugging of RTM
    /// transactional regions. This advanced debugging is enabled only if
    /// IA32_DEBUGCTL.RTM is also set.
    pub fn restricted_transactional_memory(self) -> bool {
        (self.0 >> 11) & 1 != 0
    }

    /// GD (general detect enable) flag (bit 13).
    ///
    /// Enables (when set) debug-register protection, which causes a
    /// debug exception to be generated prior to any MOV instruction that
    /// accesses a debug register. When such a condition is detected, the BD
    /// flag in debug status register DR6 is set prior to generating the
    /// exception. This condition is provided to support in-circuit
    /// emulators.
    ///
    /// When the emulator needs to access the debug registers, emulator software
    /// can set the GD flag to prevent interference from the program
    /// currently executing on the processor.
    ///
    /// The processor clears the GD flag upon entering to the debug exception
    /// handler, to allow the handler access to the debug registers.
    pub fn general_detect(self) -> bool {
        (self.0 >> 13) & 1 != 0
    }

    /// Condition for breakpoint 0 (R/W0).
    ///
    /// Specifies the breakpoint condition for the corresponding breakpoint
    /// (DR0).
    pub fn condition_0(self) -> BreakpointCondition {
        match (self.0 >> 16) & 0b11 {
            0b00 => BreakpointCondition::Execution,
            0b01 => BreakpointCondition::Write,
            0b10 => BreakpointCondition::Io,
            0b11 => BreakpointCondition::ReadWrite,
            _ => unreachable!(),
        }
    }

    /// Length for breakpoint 0 (LEN0).
    ///
    /// Specifies the size of the memory location at the address specified in
    /// the corresponding breakpoint address register (DR0).
    pub fn length_0(self) -> BreakpointLength {
        match (self.0 >> 18) & 0b11 {
            0b00 => BreakpointLength::Byte,
            0b01 => BreakpointLength::Word,
            0b10 => BreakpointLength::Quadword,
            0b11 => BreakpointLength::Dword,
            _ => unreachable!(),
        }
    }

    /// Condition for breakpoint 1 (R/W1).
    ///
    /// Specifies the breakpoint condition for the corresponding breakpoint
    /// (DR1).
    pub fn condition_1(self) -> BreakpointCondition {
        match (self.0 >> 20) & 0b11 {
            0b00 => BreakpointCondition::Execution,
            0b01 => BreakpointCondition::Write,
            0b10 => BreakpointCondition::Io,
            0b11 => BreakpointCondition::ReadWrite,
            _ => unreachable!(),
        }
    }

    /// Length for breakpoint 1 (LEN1).
    ///
    /// Specifies the size of the memory location at the address specified in
    /// the corresponding breakpoint address register (DR1).
    pub fn length_1(self) -> BreakpointLength {
        match (self.0 >> 22) & 0b11 {
            0b00 => BreakpointLength::Byte,
            0b01 => BreakpointLength::Word,
            0b10 => BreakpointLength::Quadword,
            0b11 => BreakpointLength::Dword,
            _ => unreachable!(),
        }
    }

    /// Condition for breakpoint 2 (R/W2).
    ///
    /// Specifies the breakpoint condition for the corresponding breakpoint
    /// (DR2).
    pub fn condition_2(self) -> BreakpointCondition {
        match (self.0 >> 24) & 0b11 {
            0b00 => BreakpointCondition::Execution,
            0b01 => BreakpointCondition::Write,
            0b10 => BreakpointCondition::Io,
            0b11 => BreakpointCondition::ReadWrite,
            _ => unreachable!(),
        }
    }

    /// Length for breakpoint 2 (LEN2).
    ///
    /// Specifies the size of the memory location at the address specified in
    /// the corresponding breakpoint address register (DR2).
    pub fn length_2(self) -> BreakpointLength {
        match (self.0 >> 26) & 0b11 {
            0b00 => BreakpointLength::Byte,
            0b01 => BreakpointLength::Word,
            0b10 => BreakpointLength::Quadword,
            0b11 => BreakpointLength::Dword,
            _ => unreachable!(),
        }
    }

    /// Condition for breakpoint 3 (R/W3).
    ///
    /// Specifies the breakpoint condition for the corresponding breakpoint
    /// (DR3).
    pub fn condition_3(self) -> BreakpointCondition {
        match (self.0 >> 28) & 0b11 {
            0b00 => BreakpointCondition::Execution,
            0b01 => BreakpointCondition::Write,
            0b10 => BreakpointCondition::Io,
            0b11 => BreakpointCondition::ReadWrite,
            _ => unreachable!(),
        }
    }

    /// Length for breakpoint 3 (LEN3).
    ///
    /// Specifies the size of the memory location at the address specified in
    /// the corresponding breakpoint address register (DR3).
    pub fn length_3(self) -> BreakpointLength {
        match (self.0 >> 30) & 0b11 {
            0b00 => BreakpointLength::Byte,
            0b01 => BreakpointLength::Word,
            0b10 => BreakpointLength::Quadword,
            0b11 => BreakpointLength::Dword,
            _ => unreachable!(),
        }
    }

    /// L0 through L3 (local breakpoint enable) flags (bits 0, 2, 4, and 6).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for the current task. When a breakpoint condition is detected
    /// and its associated Ln flag is set, a debug exception is generated. The
    /// processor automatically clears these flags on every task switch to
    /// avoid unwanted breakpoint conditions in the new task.
    pub fn local_breakpoint(self, index: u8) -> bool {
        match index {
            0 => self.local_breakpoint_0(),
            1 => self.local_breakpoint_1(),
            2 => self.local_breakpoint_2(),
            3 => self.local_breakpoint_3(),
            _ => false,
        }
    }

    /// G0 through G3 (global breakpoint enable) flags (bits 1, 3, 5, and 7).
    ///
    /// Enables (when set) the breakpoint condition for the associated
    /// breakpoint for all tasks. When a breakpoint condition is detected and
    /// its associated Gn flag is set, a debug exception is generated. The
    /// processor does not clear these flags on a task switch, allowing a
    /// breakpoint to be enabled for all tasks.
    pub fn global_breakpoint(self, index: u8) -> bool {
        match index {
            0 => self.global_breakpoint_0(),
            1 => self.global_breakpoint_1(),
            2 => self.global_breakpoint_2(),
            3 => self.global_breakpoint_3(),
            _ => false,
        }
    }

    /// Condition for a breakpoint.
    ///
    /// Specifies the breakpoint condition for the corresponding breakpoint
    /// (DR0-DR3).
    pub fn condition(self, index: u8) -> BreakpointCondition {
        match index {
            0 => self.condition_0(),
            1 => self.condition_1(),
            2 => self.condition_2(),
            3 => self.condition_3(),
            _ => BreakpointCondition::Execution,
        }
    }

    /// Length for a breakpoint.
    ///
    /// Specifies the size of the memory location at the address specified in
    /// the corresponding breakpoint address register (DR0-DR3).
    pub fn length(self, index: u8) -> BreakpointLength {
        match index {
            0 => self.length_0(),
            1 => self.length_1(),
            2 => self.length_2(),
            3 => self.length_3(),
            _ => BreakpointLength::Byte,
        }
    }
}

impl std::fmt::Debug for Dr7 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Dr7")
            .field("local_breakpoint_0", &self.local_breakpoint_0())
            .field("global_breakpoint_0", &self.global_breakpoint_0())
            .field("local_breakpoint_1", &self.local_breakpoint_1())
            .field("global_breakpoint_1", &self.global_breakpoint_1())
            .field("local_breakpoint_2", &self.local_breakpoint_2())
            .field("global_breakpoint_2", &self.global_breakpoint_2())
            .field("local_breakpoint_3", &self.local_breakpoint_3())
            .field("global_breakpoint_3", &self.global_breakpoint_3())
            .field("local_exact_breakpoint_0", &self.local_exact_breakpoint_0())
            .field(
                "global_exact_breakpoint_0",
                &self.global_exact_breakpoint_0(),
            )
            .field(
                "restricted_transactional_memory",
                &self.restricted_transactional_memory(),
            )
            .field("general_detect", &self.general_detect())
            .field("condition_0", &self.condition_0())
            .field("length_0", &self.length_0())
            .field("condition_1", &self.condition_1())
            .field("length_1", &self.length_1())
            .field("condition_2", &self.condition_2())
            .field("length_2", &self.length_2())
            .field("condition_3", &self.condition_3())
            .field("length_3", &self.length_3())
            .finish()
    }
}

impl From<u64> for Dr7 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr7> for u64 {
    fn from(value: Dr7) -> Self {
        value.0
    }
}
