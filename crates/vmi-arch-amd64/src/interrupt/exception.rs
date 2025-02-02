/// Exception vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionVector(pub u8);

#[expect(non_upper_case_globals)]
impl ExceptionVector {
    /// Divide Error (#DE).
    ///
    /// # Source
    ///
    /// DIV and IDIV instructions.
    pub const DivideError: Self = Self(0);

    /// Debug (#DB).
    ///
    /// # Source
    ///
    /// Any code or data reference.
    pub const DebugException: Self = Self(1);

    /// Non-maskable Interrupt.
    ///
    /// # Source
    ///
    /// Non-maskable external interrupt.
    pub const Nmi: Self = Self(2);

    /// Breakpoint (#BP).
    ///
    /// # Source
    ///
    /// INT3 instruction.
    pub const Breakpoint: Self = Self(3);

    /// Overflow (#OF).
    ///
    /// # Source
    ///
    /// INTO instruction.
    pub const Overflow: Self = Self(4);

    /// Bound Range Exceeded (#BR).
    ///
    /// # Source
    ///
    /// BOUND instruction.
    pub const BoundRange: Self = Self(5);

    /// Invalid Opcode (Undefined Opcode) (#UD).
    ///
    /// # Source
    ///
    /// UD instruction or reserved opcode.
    pub const InvalidOpcode: Self = Self(6);

    /// Device Not Available (No Math Coprocessor) (#NM).
    ///
    /// # Source
    ///
    /// Floating-point or WAIT/FWAIT instruction.
    pub const DeviceNotAvailable: Self = Self(7);

    /// Double fault (#DF).
    ///
    /// # Source
    ///
    /// Any instruction that can generate an exception, an NMI, or an INTR.
    pub const DoubleFault: Self = Self(8);

    /// CoProcessor Segment Overrun (reserved) (#MF).
    ///
    /// # Source
    ///
    /// Floating-point instruction.
    pub const CoprocessorSegmentOverrun: Self = Self(9);

    /// Invalid TSS (#TS).
    ///
    /// # Source
    ///
    /// Task switch or TSS access.
    pub const InvalidTss: Self = Self(10);

    /// Segment Not Present (#NP).
    ///
    /// # Source
    ///
    /// Loading segment registers or accessing system segments.
    pub const SegmentNotPresent: Self = Self(11);

    /// Stack Segment Fault (#SS).
    ///
    /// # Source
    ///
    /// Stack operations and SS register loads.
    pub const StackSegmentFault: Self = Self(12);

    /// General Protection Fault (#GP).
    ///
    /// # Source
    ///
    /// Any memory reference and other protection checks.
    pub const GeneralProtectionFault: Self = Self(13);

    /// Page Fault (#PF).
    ///
    /// # Source
    ///
    /// Any memory reference.
    pub const PageFault: Self = Self(14);

    /// Spurious interrupt vector.
    pub const PicSpuriousInterruptVector: Self = Self(15);

    /// Floating-Point Error (Math Fault) (#MF).
    ///
    /// # Source
    ///
    /// Floating-point or WAIT/FWAIT instruction.
    pub const MathsFault: Self = Self(16);

    /// Alignment Check (#AC).
    ///
    /// # Source
    ///
    /// Any data reference in memory.
    pub const AlignmentCheck: Self = Self(17);

    /// Machine Check (#MC).
    ///
    /// # Source
    ///
    /// Error codes (if any) and source are model dependent.
    pub const MachineCheck: Self = Self(18);

    /// SIMD Floating-Point Exception (#XM).
    ///
    /// # Source
    ///
    /// SIMD Floating-Point Instruction.
    pub const SimdException: Self = Self(19);

    /// Virtualisation Exception (#VE).
    ///
    /// # Source
    ///
    /// EPT violations.
    pub const VirtualisationException: Self = Self(20);

    /// Control Protection Exception (#CP).
    ///
    /// # Source
    ///
    /// The RET, IRET, RSTORSSP, and SETSSBSY instructions can generate this
    /// exception. When CET indirect branch tracking is enabled, this exception
    /// can be generated due to a missing ENDBRANCH instruction at the target of
    /// an indirect call or jump.
    pub const ControlFlowProtection: Self = Self(21);
    // pub const HypervisorInjection: Self = Self(28);
    // pub const VmmCommunication: Self = Self(29);
    // pub const SecurityException: Self = Self(30);

    /// Returns whether the exception vector requires an error code.
    ///
    /// These hardware exceptions must provide an error code:
    ///  - #DF (8) - always 0
    ///  - #TS (10)
    ///  - #NP (11)
    ///  - #SS (12)
    ///  - #GP (13)
    ///  - #PF (14)
    ///  - #AC (17) - always 0
    // (ref: Vol3A[6.3.1(External Interrupts)])
    pub fn requires_error_code(self) -> bool {
        matches!(
            self,
            Self::DoubleFault
                | Self::InvalidTss
                | Self::SegmentNotPresent
                | Self::StackSegmentFault
                | Self::GeneralProtectionFault
                | Self::PageFault
                | Self::AlignmentCheck
        )
    }
}
