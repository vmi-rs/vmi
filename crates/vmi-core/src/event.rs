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

bitflags::bitflags! {
    /// Flags that can be set in a VMI event response.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct VmiEventResponseFlags: u8 {
        /// Reinject the interrupt.
        const REINJECT_INTERRUPT = 1 << 0;

        /// Single-step one instruction.
        ///
        /// When set on a non-singlestep event, enables singlestep for the
        /// next instruction. When set on a singlestep event, continues
        /// singlestepping for one more instruction. When absent from a
        /// singlestep event response, singlestep is automatically disabled.
        const SINGLESTEP = 1 << 1;

        /// Fast single-step one instruction in the specified view.
        /// Unlike regular singlestep, this never generates a VMI event.
        const FAST_SINGLESTEP = 1 << 2;

        /// Emulate the instruction.
        const EMULATE = 1 << 3;
    }
}

/// A response to a VMI event.
#[derive(Debug)]
pub struct VmiEventResponse<Arch>
where
    Arch: Architecture,
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
    Arch: Architecture,
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
    Arch: Architecture,
{
    /// Creates a response to reinject an interrupt.
    pub fn reinject_interrupt() -> Self {
        Self::default().and_reinject_interrupt()
    }

    /// Creates a response to single-step one instruction.
    pub fn singlestep() -> Self {
        Self::default().and_singlestep()
    }

    /// Creates a response to fast single-step one instruction in the
    /// specified view. Unlike regular singlestep, fast singlestep never
    /// generates a VMI event.
    pub fn fast_singlestep(view: View) -> Self {
        Self::default().and_fast_singlestep(view)
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

    /// Adds the single-step flag to the response.
    pub fn and_singlestep(self) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::SINGLESTEP,
            ..self
        }
    }

    /// Adds the fast single-step flag to the response.
    pub fn and_fast_singlestep(self, view: View) -> Self {
        Self {
            flags: self.flags | VmiEventResponseFlags::FAST_SINGLESTEP,
            view: Some(view),
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
