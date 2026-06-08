use vmi_core::{Gfn, MemoryAccess, Pa, Va};

use crate::Interrupt;

/// Event generated when monitored memory is accessed.
#[derive(Debug, Clone, Copy)]
pub struct EventMemoryAccess {
    /// Physical address that was accessed.
    pub pa: Pa,

    /// Virtual address that was accessed.
    pub va: Va,

    /// Type of access that occurred (read/write/execute).
    pub access: MemoryAccess,
}

/// EL1 VM system registers monitorable via `KVM_VMI_EVENT_SYSREG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    /// `SCTLR_EL1`.
    SctlrEl1,

    /// `TTBR0_EL1` (user translation root, the arm64 CR3 analog).
    Ttbr0El1,

    /// `TTBR1_EL1`.
    Ttbr1El1,

    /// `TCR_EL1`.
    TcrEl1,

    /// `CONTEXTIDR_EL1`.
    ContextidrEl1,

    /// `MAIR_EL1`.
    MairEl1,
}

impl SystemRegister {
    /// Maps to the stable `KVM_VMI_SYSREG_*` index.
    pub fn to_kvm_index(self) -> u32 {
        match self {
            Self::SctlrEl1 => 0,
            Self::Ttbr0El1 => 1,
            Self::Ttbr1El1 => 2,
            Self::TcrEl1 => 3,
            Self::ContextidrEl1 => 4,
            Self::MairEl1 => 5,
        }
    }

    /// Recovers a `SystemRegister` from a `KVM_VMI_SYSREG_*` index.
    pub fn from_kvm_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::SctlrEl1),
            1 => Some(Self::Ttbr0El1),
            2 => Some(Self::Ttbr1El1),
            3 => Some(Self::TcrEl1),
            4 => Some(Self::ContextidrEl1),
            5 => Some(Self::MairEl1),
            _ => None,
        }
    }
}

/// Event generated when a monitored EL1 system register is written.
#[derive(Debug, Clone, Copy)]
pub struct EventWriteSystemRegister {
    /// The system register that was written.
    pub register: SystemRegister,

    /// New value the guest is writing (observe-only).
    pub new_value: u64,

    /// Old value before the (deferred) write.
    pub old_value: u64,
}

/// Event generated when an interrupt or exception occurs.
#[derive(Debug, Clone, Copy)]
pub struct EventInterrupt {
    /// Returns the GFN of the instruction that raised the interrupt.
    pub gfn: Gfn,

    /// Information about the interrupt or exception.
    pub interrupt: Interrupt,
}

/// Event generated after a single instruction step completes.
///
/// Carries no payload. The stepped instruction's address is read from the
/// vCPU registers, not from the event.
#[derive(Debug, Clone, Copy)]
pub struct EventSinglestep;

/// Classifies why a KVM VMI event fired.
#[derive(Debug, Clone, Copy)]
pub enum EventReason {
    /// Memory access event (read/write/execute).
    MemoryAccess(EventMemoryAccess),

    /// System-register write event.
    WriteSystemRegister(EventWriteSystemRegister),

    /// Interrupt or exception event.
    Interrupt(EventInterrupt),

    /// Single-step event.
    Singlestep(EventSinglestep),
}

impl EventReason {
    /// Returns the system-register write event.
    ///
    /// # Panics
    ///
    /// Panics if the event reason is not a system-register write event.
    pub fn as_write_system_register(&self) -> &EventWriteSystemRegister {
        match self {
            Self::WriteSystemRegister(write_system_register) => write_system_register,
            _ => panic!("EventReason is not a WriteSystemRegister"),
        }
    }
}

/// Specifies which hardware events should be monitored.
#[derive(Debug, Clone, Copy)]
pub enum EventMonitor {
    /// Monitor writes to a specific EL1 system register.
    Register(SystemRegister),

    /// Monitor singlestep execution of instructions.
    Singlestep,

    /// Monitor guest software breakpoints (`BRK`).
    Breakpoint,
}

#[cfg(test)]
mod tests {
    use super::SystemRegister;

    #[test]
    fn system_register_index_round_trip() {
        for register in [
            SystemRegister::SctlrEl1,
            SystemRegister::Ttbr0El1,
            SystemRegister::Ttbr1El1,
            SystemRegister::TcrEl1,
            SystemRegister::ContextidrEl1,
            SystemRegister::MairEl1,
        ] {
            assert_eq!(
                SystemRegister::from_kvm_index(register.to_kvm_index()),
                Some(register)
            );
        }
    }
}
