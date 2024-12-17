mod event;
mod registers;

use vmi_arch_amd64::{Amd64, ControlRegister, EventMonitor, EventReason, ExceptionVector};
use vmi_core::{
    Registers as _, VcpuId, View, VmiEvent, VmiEventFlags, VmiEventResponse, VmiEventResponseFlags,
};
use xen::ctrl::{
    VmEvent, VmEventData, VmEventFastSinglestep, VmEventFlag, VmEventFlagOptions, VmEventRegs,
};

use crate::{ArchAdapter, Error, IntoExt as _, TryFromExt, XenDriver};

impl ArchAdapter for Amd64 {
    type XenArch = xen::arch::x86::Amd64;

    fn registers(driver: &XenDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, Error> {
        Ok(driver.domain.get_context_cpu(vcpu.into_ext())?.into_ext())
    }

    fn set_registers(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), Error> {
        Ok(driver
            .domain
            .set_context_cpu(vcpu.into_ext(), registers.into_ext())?)
    }

    fn monitor_enable(driver: &XenDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        const ENABLE: bool = true;
        const SYNC: bool = true;
        const ON_CHANGE_ONLY: bool = true;

        match option {
            EventMonitor::Register(register) => {
                driver.monitor.write_ctrlreg(
                    register.into_ext(),
                    ENABLE,
                    SYNC,
                    0,
                    ON_CHANGE_ONLY,
                )?;
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => driver.monitor.debug_exceptions(ENABLE, SYNC)?,
                ExceptionVector::Breakpoint => driver.monitor.software_breakpoint(ENABLE)?,
                _ => return Err(Error::NotSupported),
            },
            EventMonitor::Singlestep => driver.monitor.singlestep(ENABLE)?,
            EventMonitor::GuestRequest { allow_userspace } => {
                driver
                    .monitor
                    .guest_request(ENABLE, SYNC, allow_userspace)?
            }
            EventMonitor::CpuId => driver.monitor.cpuid(ENABLE)?,
            EventMonitor::Io => driver.monitor.io(ENABLE)?,
        }

        Ok(())
    }

    fn monitor_disable(driver: &XenDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        const DISABLE: bool = false;
        const SYNC: bool = true;
        const ON_CHANGE_ONLY: bool = true;

        match option {
            EventMonitor::Register(register) => {
                driver.monitor.write_ctrlreg(
                    register.into_ext(),
                    DISABLE,
                    SYNC,
                    0,
                    ON_CHANGE_ONLY,
                )?;
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => {
                    driver.monitor.debug_exceptions(DISABLE, SYNC)?
                }
                ExceptionVector::Breakpoint => driver.monitor.software_breakpoint(DISABLE)?,
                _ => return Err(Error::NotSupported),
            },
            EventMonitor::Singlestep => {
                for vcpu in 0..=driver.info.max_vcpu_id {
                    let _ = driver.domain.debug_control(vcpu.into(), 0);
                }

                driver.monitor.singlestep(DISABLE)?;
            }
            EventMonitor::GuestRequest { .. } => {
                driver.monitor.guest_request(DISABLE, SYNC, false)?
            }
            EventMonitor::CpuId => driver.monitor.cpuid(DISABLE)?,
            EventMonitor::Io => driver.monitor.io(DISABLE)?,
        }

        Ok(())
    }

    fn inject_interrupt(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), Error> {
        Ok(driver.devicemodel.inject_event(
            vcpu.into_ext(),
            interrupt.vector.into_ext(),
            interrupt.typ.into_ext(),
            interrupt.error_code,
            interrupt.instruction_length,
            interrupt.extra,
        )?)
    }

    fn process_event(
        driver: &XenDriver<Self>,
        event: &mut VmEvent,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error> {
        // Convert the Xen event to a VMI event.
        let vmi_reason = match EventReason::try_from_ext(&event.reason) {
            Ok(reason) => reason,
            Err(_) => return Err(Error::NotSupported),
        };

        let mut registers = match &event.data {
            Some(VmEventData::Registers(VmEventRegs::X86(regs))) => regs.into_ext(),
            _ => Self::Registers::default(),
        };

        let view = event
            .flags
            .contains(VmEventFlag::ALTERNATE_P2M)
            .then_some(View(event.altp2m_idx));

        let mut flags = VmiEventFlags::default();
        if event.flags.contains(VmEventFlag::VCPU_PAUSED) {
            flags |= VmiEventFlags::VCPU_PAUSED;
        }

        let vcpu_id = event.vcpu_id.into_ext();

        let vmi_event = VmiEvent::new(vcpu_id, flags, view, registers, vmi_reason);

        // Handle the event.
        let vmi_response = handler(&vmi_event);

        // Update the Xen event.
        event.flags &= VmEventFlag::VCPU_PAUSED;
        if let Some(view) = vmi_response.view {
            event.flags |= VmEventFlag::ALTERNATE_P2M;
            event.altp2m_idx = view.0;
        }

        if let Some(new_registers) = vmi_response.registers {
            registers.set_gp_registers(&new_registers);
            event.flags |= VmEventFlag::SET_REGISTERS;
            event.data = Some(VmEventData::Registers(VmEventRegs::X86(
                registers.into_ext(),
            )));
        }
        else {
            event.data = None;
        }

        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::REINJECT_INTERRUPT)
        {
            match vmi_event.reason() {
                EventReason::Interrupt(data) => {
                    driver.devicemodel.inject_event(
                        event.vcpu_id,
                        data.interrupt.vector.into_ext(),
                        data.interrupt.typ.into_ext(),
                        data.interrupt.error_code,
                        data.interrupt.instruction_length,
                        data.interrupt.extra,
                    )?;
                }
                _ => {
                    tracing::warn!(
                        "Attempted to reinject interrupt when current event is not an interrupt"
                    );
                }
            }
        }

        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::TOGGLE_SINGLESTEP)
        {
            event.flags |= VmEventFlag::TOGGLE_SINGLESTEP;
        }

        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::TOGGLE_FAST_SINGLESTEP)
        {
            event.flags |= VmEventFlag::FAST_SINGLESTEP;
            event.options = Some(VmEventFlagOptions {
                fast_singlestep: Some(VmEventFastSinglestep {
                    p2midx: view.map(|v| v.0).unwrap_or(0),
                }),
            });
        }

        if vmi_response.flags.contains(VmiEventResponseFlags::EMULATE) {
            event.flags |= VmEventFlag::EMULATE;
        }

        Ok(())
    }

    fn reset_state(driver: &XenDriver<Self>) -> Result<(), Error> {
        let _ = driver.monitor_disable(EventMonitor::Io);
        let _ = driver.monitor_disable(EventMonitor::CpuId);
        let _ = driver.monitor_disable(EventMonitor::GuestRequest {
            allow_userspace: false,
        });
        let _ = driver.monitor_disable(EventMonitor::Singlestep);
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint));
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::DebugException));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Xcr0));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr4));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr3));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr0));
        let _ = driver.altp2m.reset_view();
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
