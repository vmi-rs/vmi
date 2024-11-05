/// Exception vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionVector {
    /// Divide Error (#DE).
    ///
    /// # Source
    ///
    /// DIV and IDIV instructions.
    DivideError = 0,

    /// Debug (#DB).
    ///
    /// # Source
    ///
    /// Any code or data reference.
    DebugException = 1,

    /// Non-maskable Interrupt.
    ///
    /// # Source
    ///
    /// Non-maskable external interrupt.
    Nmi = 2,

    /// Breakpoint (#BP).
    ///
    /// # Source
    ///
    /// INT3 instruction.
    Breakpoint = 3,

    /// Overflow (#OF).
    ///
    /// # Source
    ///
    /// INTO instruction.
    Overflow = 4,

    /// Bound Range Exceeded (#BR).
    ///
    /// # Source
    ///
    /// BOUND instruction.
    BoundRange = 5,

    /// Invalid Opcode (Undefined Opcode) (#UD).
    ///
    /// # Source
    ///
    /// UD instruction or reserved opcode.
    InvalidOpcode = 6,

    /// Device Not Available (No Math Coprocessor) (#NM).
    ///
    /// # Source
    ///
    /// Floating-point or WAIT/FWAIT instruction.
    DeviceNotAvailable = 7,

    /// Double fault (#DF).
    ///
    /// # Source
    ///
    /// Any instruction that can generate an exception, an NMI, or an INTR.
    DoubleFault = 8,

    /// CoProcessor Segment Overrun (reserved) (#MF).
    ///
    /// # Source
    ///
    /// Floating-point instruction.
    CoprocessorSegmentOverrun = 9,

    /// Invalid TSS (#TS).
    ///
    /// # Source
    ///
    /// Task switch or TSS access.
    InvalidTss = 10,

    /// Segment Not Present (#NP).
    ///
    /// # Source
    ///
    /// Loading segment registers or accessing system segments.
    SegmentNotPresent = 11,

    /// Stack Segment Fault (#SS).
    ///
    /// # Source
    ///
    /// Stack operations and SS register loads.
    StackSegmentFault = 12,

    /// General Protection Fault (#GP).
    ///
    /// # Source
    ///
    /// Any memory reference and other protection checks.
    GeneralProtectionFault = 13,

    /// Page Fault (#PF).
    ///
    /// # Source
    ///
    /// Any memory reference.
    PageFault = 14,

    /// Spurious interrupt vector.
    PicSpuriousInterruptVector = 15,

    /// Floating-Point Error (Math Fault) (#MF).
    ///
    /// # Source
    ///
    /// Floating-point or WAIT/FWAIT instruction.
    MathsFault = 16,

    /// Alignment Check (#AC).
    ///
    /// # Source
    ///
    /// Any data reference in memory.
    AlignmentCheck = 17,

    /// Machine Check (#MC).
    ///
    /// # Source
    ///
    /// Error codes (if any) and source are model dependent.
    MachineCheck = 18,

    /// SIMD Floating-Point Exception (#XM).
    ///
    /// # Source
    ///
    /// SIMD Floating-Point Instruction.
    SimdException = 19,

    /// Virtualisation Exception (#VE).
    ///
    /// # Source
    ///
    /// EPT violations.
    VirtualisationException = 20,

    /// Control Protection Exception (#CP).
    ///
    /// # Source
    ///
    /// The RET, IRET, RSTORSSP, and SETSSBSY instructions can generate this
    /// exception. When CET indirect branch tracking is enabled, this exception
    /// can be generated due to a missing ENDBRANCH instruction at the target of
    /// an indirect call or jump.
    ControlFlowProtection = 21,
    // HypervisorInjection = 28,
    // VmmCommunication = 29,
    // SecurityException = 30,
}

impl ExceptionVector {
    /// Returns the exception vector for the given vector number.
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
    pub fn requires_error_code_for_vector(vector: u8) -> bool {
        match vector {
            vector if vector == ExceptionVector::DoubleFault as u8 => true,
            vector if vector == ExceptionVector::InvalidTss as u8 => true,
            vector if vector == ExceptionVector::SegmentNotPresent as u8 => true,
            vector if vector == ExceptionVector::StackSegmentFault as u8 => true,
            vector if vector == ExceptionVector::GeneralProtectionFault as u8 => true,
            vector if vector == ExceptionVector::PageFault as u8 => true,
            vector if vector == ExceptionVector::AlignmentCheck as u8 => true,
            _ => false,
        }
    }

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
