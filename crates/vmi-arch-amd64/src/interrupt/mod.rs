mod exception;
pub use self::exception::ExceptionVector;

mod idt;
use vmi_core::Va;

pub use self::idt::{Idt, IdtAccess, IdtEntry};

/// Type of interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// External interrupt.
    ExternalInterrupt,

    /// Reserved.
    Reserved,

    /// NMI.
    Nmi,

    /// Hardware exception.
    HardwareException,

    /// Software interrupt (CD nn).
    SoftwareInterrupt,

    /// ICEBP (F1).
    PrivilegedSoftwareException,

    /// INT3 (CC), INTO (CE).
    SoftwareException,
}

/// Information about an interrupt or exception.
#[derive(Debug, Clone, Copy)]
pub struct Interrupt {
    /// Vector number of the interrupt.
    pub vector: ExceptionVector,

    /// Type of interrupt.
    pub typ: InterruptType,

    /// Error code associated with the interrupt.
    pub error_code: u32,

    /// Length of the instruction that caused the interrupt.
    pub instruction_length: u8,

    /// Extra information about the interrupt.
    ///
    /// For page faults, this is the virtual address that caused the fault
    /// (i.e., `CR2`).
    pub extra: u64,
}

impl Interrupt {
    /// Creates a new software breakpoint exception.
    pub fn breakpoint(instruction_length: u8) -> Self {
        Self {
            vector: ExceptionVector::Breakpoint,
            typ: InterruptType::SoftwareException,
            error_code: 0xffff_ffff,
            instruction_length,
            extra: 0,
        }
    }

    /// Creates a new page fault exception.
    pub fn page_fault(va: Va, error_code: u32) -> Self {
        Self {
            vector: ExceptionVector::PageFault,
            typ: InterruptType::HardwareException,
            error_code,
            instruction_length: 0,
            extra: va.into(),
        }
    }
}
