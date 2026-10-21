mod exception;
pub use self::exception::ExceptionVector;

mod idt;
mod page_fault;
use vmi_core::Va;

pub use self::{
    idt::{Idt, IdtAccess, IdtEntry},
    page_fault::PageFaultErrorCode,
};

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

    /// Error code associated with the interrupt, if it has one.
    pub error_code: Option<u32>,

    /// Length of the instruction that caused the interrupt.
    pub instruction_length: u8,

    /// Extra information about the interrupt.
    ///
    /// For page faults, this is the virtual address that caused the fault
    /// (i.e., `CR2`).
    pub extra: u64,
}

impl Interrupt {
    /// Creates a new page fault exception with the given error code.
    ///
    /// [`vmi_core::arch::Interrupt::page_fault`] builds the error code from a
    /// [`PageFault`](vmi_core::PageFault) instead.
    pub fn page_fault_with_error_code(va: Va, error_code: PageFaultErrorCode) -> Self {
        Self {
            vector: ExceptionVector::PageFault,
            typ: InterruptType::HardwareException,
            error_code: Some(error_code.bits()),
            instruction_length: 0,
            extra: va.into(),
        }
    }
}
