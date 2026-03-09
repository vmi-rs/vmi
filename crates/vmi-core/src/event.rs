use crate::{Architecture, Registers, VcpuId, View};

bitflags::bitflags! {
    /// Flags that can be set in a VMI event.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct VmiEventFlags: u8 {
        /// The virtual CPU is paused.
        const VCPU_PAUSED = 1 << 0;
    }
}

/// An event that occurred during VMI.
#[derive(Debug, Clone, Copy)]
pub struct VmiEvent<Arch>
where
    Arch: Architecture,
{
    /// The ID of the virtual CPU where the event occurred.
    vcpu_id: VcpuId,

    /// Flags associated with the event.
    flags: VmiEventFlags,

    /// The view associated with the event, if any.
    view: Option<View>,

    /// The CPU register state at the time of the event.
    registers: Arch::Registers,

    /// The reason for the event.
    reason: Arch::EventReason,
}

impl<Arch> VmiEvent<Arch>
where
    Arch: Architecture,
{
    /// Creates a new VMI event.
    pub fn new(
        vcpu_id: VcpuId,
        flags: VmiEventFlags,
        view: Option<View>,
        registers: Arch::Registers,
        reason: Arch::EventReason,
    ) -> Self {
        Self {
            vcpu_id,
            flags,
            view,
            registers,
            reason,
        }
    }

    /// Returns the ID of the virtual CPU where the event occurred.
    pub fn vcpu_id(&self) -> VcpuId {
        self.vcpu_id
    }

    /// Returns flags associated with the event.
    pub fn flags(&self) -> VmiEventFlags {
        self.flags
    }

    /// Returns the view associated with the event, if any.
    pub fn view(&self) -> Option<View> {
        self.view
    }

    /// Returns a reference to the CPU registers at the time of the event.
    pub fn registers(&self) -> &Arch::Registers {
        &self.registers
    }

    /// Returns a reference to the reason for the event.
    pub fn reason(&self) -> &Arch::EventReason {
        &self.reason
    }
}

/// The primary action to take when resuming from a VMI event.
///
/// These actions are mutually exclusive. Each variant maps to a distinct
/// hypervisor resume behavior.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VmiEventAction {
    /// Resume the vCPU normally, allowing the trapped instruction to
    /// proceed with its original side effects.
    #[default]
    Continue,

    /// Deny the event (suppress CR/MSR write side effects).
    ///
    /// The instruction has already executed and RIP has advanced, but the
    /// register write is not committed. Effectively makes the instruction
    /// a no-op.
    Deny,

    /// Reinject the interrupt back into the guest.
    ///
    /// Used when a monitored interrupt (e.g. INT3) was not placed by us
    /// and should be delivered to the guest's own interrupt handler.
    ReinjectInterrupt,

    /// Single-step one instruction.
    ///
    /// When returned from a non-singlestep event, enables singlestep for
    /// the next instruction. When returned from a singlestep event,
    /// continues singlestepping for one more instruction. When absent
    /// from a singlestep event response, singlestep is automatically
    /// disabled.
    Singlestep,

    /// Fast single-step one instruction in the response's view, then
    /// silently switch back to the event's original view. Unlike regular
    /// singlestep, this never generates a VMI event.
    FastSinglestep,

    /// Emulate the faulting instruction inside the hypervisor instead of
    /// returning to the guest. Useful for handling read/write memory
    /// access events without switching views.
    Emulate,
}

/// A response to a VMI event.
#[derive(Debug)]
pub struct VmiEventResponse<Arch>
where
    Arch: Architecture,
{
    /// The primary action to take when resuming.
    pub action: VmiEventAction,

    /// The view to set for the vCPU.
    pub view: Option<View>,

    /// The vCPU registers to set.
    pub registers: Option<<Arch::Registers as Registers>::GpRegisters>,
}

impl<Arch> Default for VmiEventResponse<Arch>
where
    Arch: Architecture,
{
    fn default() -> Self {
        Self {
            action: VmiEventAction::Continue,
            view: None,
            registers: None,
        }
    }
}

impl<Arch> VmiEventResponse<Arch>
where
    Arch: Architecture,
{
    /// Creates a response to deny the event.
    pub fn deny() -> Self {
        Self {
            action: VmiEventAction::Deny,
            ..Self::default()
        }
    }

    /// Creates a response to reinject an interrupt.
    pub fn reinject_interrupt() -> Self {
        Self {
            action: VmiEventAction::ReinjectInterrupt,
            ..Self::default()
        }
    }

    /// Creates a response to single-step one instruction.
    pub fn singlestep() -> Self {
        Self {
            action: VmiEventAction::Singlestep,
            ..Self::default()
        }
    }

    /// Creates a response to fast single-step one instruction in the
    /// specified view. Unlike regular singlestep, fast singlestep never
    /// generates a VMI event.
    pub fn fast_singlestep(view: View) -> Self {
        Self {
            action: VmiEventAction::FastSinglestep,
            view: Some(view),
            ..Self::default()
        }
    }

    /// Creates a response to emulate the instruction.
    pub fn emulate() -> Self {
        Self {
            action: VmiEventAction::Emulate,
            ..Self::default()
        }
    }

    /// Sets a specific view for the response.
    pub fn with_view(self, view: View) -> Self {
        Self {
            view: Some(view),
            ..self
        }
    }

    /// Sets specific CPU registers for the response.
    pub fn with_registers(self, registers: <Arch::Registers as Registers>::GpRegisters) -> Self {
        Self {
            registers: Some(registers),
            ..self
        }
    }
}
