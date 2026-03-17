/// Interrupt injection types for AArch64.
#[derive(Debug, Clone, Copy)]
pub enum Interrupt {
    /// Synchronous exception — encoded as full ESR value.
    Sync(SyncException),
    /// Asynchronous SError — ISS portion only.
    SError {
        /// Instruction Specific Syndrome bits.
        iss: u32,
    },
}

/// Synchronous exception types.
#[derive(Debug, Clone, Copy)]
pub enum SyncException {
    /// Data abort (EC=0x24 same EL, EC=0x25 lower EL).
    DataAbort {
        /// Instruction Specific Syndrome bits.
        iss: u32,
        /// Instruction Length. true = 32-bit instruction.
        il: bool,
    },
    /// Instruction abort (EC=0x20 same EL, EC=0x21 lower EL).
    InstructionAbort {
        /// Instruction Specific Syndrome bits.
        iss: u32,
        /// Instruction Length.
        il: bool,
    },
    /// BRK instruction (EC=0x3C).
    Brk {
        /// Immediate value from BRK #imm16.
        comment: u16,
    },
    /// SVC instruction (EC=0x15).
    Svc {
        /// Immediate value from SVC #imm16.
        imm16: u16,
    },
    /// HVC instruction (EC=0x16).
    Hvc {
        /// Immediate value from HVC #imm16.
        imm16: u16,
    },
    /// Raw ESR value for other exception classes.
    Raw {
        /// Full ESR value.
        esr: u64,
    },
}

impl SyncException {
    /// Encode this exception as an ESR_EL2 value.
    pub fn to_esr(self) -> u64 {
        match self {
            Self::DataAbort { iss, il: true } => (0x25u64 << 26) | (1 << 25) | iss as u64,
            Self::DataAbort { iss, il: false } => (0x24u64 << 26) | iss as u64,
            Self::InstructionAbort { iss, il: true } => (0x21u64 << 26) | (1 << 25) | iss as u64,
            Self::InstructionAbort { iss, il: false } => (0x20u64 << 26) | iss as u64,
            Self::Brk { comment } => (0x3Cu64 << 26) | (1 << 25) | comment as u64,
            Self::Svc { imm16 } => (0x15u64 << 26) | (1 << 25) | imm16 as u64,
            Self::Hvc { imm16 } => (0x16u64 << 26) | (1 << 25) | imm16 as u64,
            Self::Raw { esr } => esr,
        }
    }
}
