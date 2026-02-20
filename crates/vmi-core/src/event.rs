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
    Arch: Architecture + ?Sized,
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
    Arch: Architecture + ?Sized,
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

bitflags::bitflags! {
    /// Flags that can be set in a VMI event response.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct VmiEventResponseFlags: u8 {
        /// Reinject the interrupt.
        const REINJECT_INTERRUPT = 1 << 0;

        /// Toggle single-step mode.
        const TOGGLE_SINGLESTEP = 1 << 1;

        /// Toggle fast single-step mode.
        const TOGGLE_FAST_SINGLESTEP = 1 << 2;

        /// Emulate the instruction.
        const EMULATE = 1 << 3;
    }
}

/// A response to a VMI event.
#[derive(Debug)]
pub struct VmiEventResponse<Arch>
where
    Arch: Architecture + ?Sized,
{
    /// Flags associated with the response.
    pub flags: VmiEventResponseFlags,

    /// The view to set for the vCPU.
    pub view: Option<View>,

    /// The vCPU registers to set.
    pub registers: Option<<Arch::Registers as Registers>::GpRegisters>,
}

impl<Arch> Default for VmiEventResponse<Arch>
where
    Arch: Architecture + ?Sized,
{
    fn default() -> Self {
        Self {
            flags: VmiEventResponseFlags::empty(),
            view: None,
            registers: None,
        }
    }
}

impl<Arch> VmiEventResponse<Arch>
where
    Arch: Architecture + ?Sized,
{
    /// Creates a response to reinject an interrupt.
    pub fn reinject_interrupt() -> Self {
        Self::default().and_reinject_interrupt()
    }

    /// Creates a response to toggle single-step mode.
    pub fn toggle_singlestep() -> Self {
        Self::default().and_toggle_singlestep()
    }

    /// Creates a response to toggle fast single-step mode.
    pub fn toggle_fast_singlestep() -> Self {
        Self::default().and_toggle_fast_singlestep()
    }

    /// Creates a response to emulate the instruction.
    pub fn emulate() -> Self {
        Self::default().and_emulate()
    }

    /// Creates a response to set a specific view.
    pub fn set_view(view: View) -> Self {
        Self::default().and_set_view(view)
    }

    /// Creates a response to set specific CPU registers.
    pub fn set_registers(registers: <Arch::Registers as Registers>::GpRegisters) -> Self {
        Self::default().and_set_registers(registers)
    }

    /// Adds the reinject interrupt flag to the response.
    pub fn and_reinject_interrupt(self) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::REINJECT_INTERRUPT,
            ..self
        }
    }

    /// Adds the toggle single-step flag to the response.
    pub fn and_toggle_singlestep(self) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::TOGGLE_SINGLESTEP,
            ..self
        }
    }

    /// Adds the toggle fast single-step flag to the response.
    pub fn and_toggle_fast_singlestep(self) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::TOGGLE_FAST_SINGLESTEP,
            ..self
        }
    }

    /// Adds the emulate flag to the response.
    pub fn and_emulate(self) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::EMULATE,
            ..self
        }
    }

    /// Sets a specific view for the response.
    pub fn and_set_view(self, view: View) -> Self {
        Self {
            view: Some(view),
            ..self
        }
    }

    /// Sets specific CPU registers for the response.
    pub fn and_set_registers(self, registers: <Arch::Registers as Registers>::GpRegisters) -> Self {
        Self {
            registers: Some(registers),
            ..self
        }
    }
}
