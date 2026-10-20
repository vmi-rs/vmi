//! AArch64 bridge adapter.
//!
//! # Register layout
//!
//! The guest makes a bridge call with `BRK #0x4d56`, a `BRK` whose comment
//! is [`BREAKPOINT_COMMENT`]. The instruction raises a breakpoint exception.
//! While the monitor enables [`EventMonitor::Breakpoint`], the hypervisor
//! reports the exception as an [`EventReason::Interrupt`] whose
//! [`Interrupt::breakpoint_comment`] is [`BREAKPOINT_COMMENT`].
//!
//! A `BRK` consumes no register, so each field of the packet has a register
//! of its own:
//!
//! | Field           | Register           |
//! |-----------------|--------------------|
//! | magic           | `W0`               |
//! | request         | `X1` (bits 15:0)   |
//! | method          | `X1` (bits 31:16)  |
//! | value1          | `X2`               |
//! | value2          | `X3`               |
//! | value3          | `X4`               |
//! | value4          | `X5`               |
//!
//! The response values go to `X0` to `X3`.
//!
//! The exception reports the address of the `BRK` itself. The monitor
//! resumes the guest after the instruction, [`Arm64::INSTRUCTION_SIZE`]
//! bytes further.
//!
//! # Without a monitor
//!
//! Without the breakpoint monitor, the guest's kernel handles the exception.
//! In user mode, the caller then gets a signal, such as `SIGTRAP` on macOS,
//! which ends the process unless the process handles the signal. A caller
//! that has to survive a missing monitor handles the signal. Its handler sets
//! `X0` to `X3` of the interrupted context to zero and resumes after the
//! `BRK`. The zero response then fails the verification of the guest side,
//! as the reply of Xen does when no monitor answers a `VMCALL`.
//!
//! A monitor re-injects the exception of a packet that no handler takes. The
//! guest then handles the exception as without a monitor.
//!
//! [`EventMonitor::Breakpoint`]: vmi_arch_arm64::EventMonitor::Breakpoint
//! [`EventReason::Interrupt`]: vmi_arch_arm64::EventReason::Interrupt
//! [`Interrupt::breakpoint_comment`]: vmi_arch_arm64::Interrupt::breakpoint_comment

use vmi_arch_arm64::{Arm64, GpRegisters, PagingGeometry};
use vmi_core::VmiEvent;

use super::{super::BridgePacket, ArchAdapter, GpRegistersAdapter};

/// Comment of the `BRK` instruction that makes a bridge call on AArch64.
///
/// The value is `VM` in ASCII, read as a little-endian `u16`.
pub const BREAKPOINT_COMMENT: u16 = 0x4d56;

impl<Geometry> ArchAdapter for Arm64<Geometry>
where
    Geometry: PagingGeometry + 'static,
{
    fn read_packet(event: &VmiEvent<Self>) -> BridgePacket {
        let registers = &event.registers().regs;

        BridgePacket::new(
            registers[0] as u32,
            registers[1] as u16,
            (registers[1] >> 16) as u16,
        )
        .with_value1(registers[2])
        .with_value2(registers[3])
        .with_value3(registers[4])
        .with_value4(registers[5])
    }
}

/// Writes response values into AArch64 general-purpose registers.
///
/// Maps value1-value4 to `X0`-`X3`.
impl<Geometry> GpRegistersAdapter for GpRegisters<Geometry>
where
    Geometry: PagingGeometry + 'static,
{
    fn write_response(
        &mut self,
        value1: Option<u64>,
        value2: Option<u64>,
        value3: Option<u64>,
        value4: Option<u64>,
    ) {
        let values = [value1, value2, value3, value4];
        for (register, value) in self.regs.iter_mut().zip(values) {
            if let Some(value) = value {
                *register = value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vmi_arch_arm64::{EventInterrupt, EventReason, Granule16KVa47, Interrupt, Registers};
    use vmi_core::{Gfn, Registers as _, VcpuId, VmiEvent, VmiEventFlags};

    use super::*;

    /// Architecture of the test events.
    type Arch = Arm64<Granule16KVa47>;

    #[test]
    fn packet_ignores_upper_register_halves() {
        let mut registers = Registers::<Granule16KVa47>::default();
        registers.regs[..6].copy_from_slice(&[
            0xffff_ffff_4249_4d56,
            0xffff_ffff_0002_0d01,
            1,
            2,
            3,
            4,
        ]);
        let interrupt = Interrupt::software_breakpoint(BREAKPOINT_COMMENT);
        let event = VmiEvent::<Arch>::new(
            VcpuId(0),
            VmiEventFlags::empty(),
            None,
            registers,
            EventReason::Interrupt(EventInterrupt::new(Gfn(0), interrupt)),
        );

        let packet = Arch::read_packet(&event);

        assert_eq!(packet.magic(), 0x4249_4d56);
        assert_eq!(packet.request(), 0x0d01);
        assert_eq!(packet.method(), 0x0002);
        assert_eq!(
            [
                packet.value1(),
                packet.value2(),
                packet.value3(),
                packet.value4()
            ],
            [1, 2, 3, 4]
        );
    }

    #[test]
    fn response_leaves_unset_values_unchanged() {
        let mut registers = Registers::<Granule16KVa47>::default();
        registers.regs[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let mut gp_registers = registers.gp_registers();

        gp_registers.write_response(Some(10), None, Some(30), Some(40));

        assert_eq!(gp_registers.regs[..5], [10, 2, 30, 40, 5]);
    }
}
