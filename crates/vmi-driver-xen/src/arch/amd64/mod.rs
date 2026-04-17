mod event;
mod registers;

use vmi_arch_amd64::{Amd64, ControlRegister, EventMonitor, EventReason, ExceptionVector, Msr};
use vmi_core::{
    Registers as _, VcpuId, View, VmiEvent, VmiEventAction, VmiEventFlags, VmiEventResponse,
};
use xen::ctrl::{
    VmEvent, VmEventData, VmEventFastSinglestep, VmEventFlag, VmEventFlagOptions, VmEventRegs,
};

use crate::{ArchAdapter, IntoExt as _, TryFromExt as _, XenDriver, XenDriverError};

impl ArchAdapter for Amd64 {
    type XenArch = xen::arch::x86::Amd64;

    fn registers(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
    ) -> Result<Self::Registers, XenDriverError> {
        Ok(driver.domain.get_context_cpu(vcpu.into_ext())?.into_ext())
    }

    fn set_registers(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), XenDriverError> {
        Ok(driver
            .domain
            .set_context_cpu(vcpu.into_ext(), registers.into_ext())?)
    }

    fn monitor_enable(
        driver: &XenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), XenDriverError> {
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
            EventMonitor::Msr(msr) => {
                driver
                    .monitor
                    .mov_to_msr(msr.into(), ENABLE, ON_CHANGE_ONLY)?
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => driver.monitor.debug_exceptions(ENABLE, SYNC)?,
                ExceptionVector::Breakpoint => driver.monitor.software_breakpoint(ENABLE)?,
                _ => return Err(XenDriverError::NotSupported),
            },
            EventMonitor::Singlestep => driver.monitor.singlestep(ENABLE)?,
            EventMonitor::Hypercall { allow_userspace } => {
                driver
                    .monitor
                    .guest_request(ENABLE, SYNC, allow_userspace)?
            }
            EventMonitor::CpuId => driver.monitor.cpuid(ENABLE)?,
            EventMonitor::Io => driver.monitor.io(ENABLE)?,
        }

        Ok(())
    }

    fn monitor_disable(
        driver: &XenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), XenDriverError> {
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
            EventMonitor::Msr(msr) => {
                driver
                    .monitor
                    .mov_to_msr(msr.into(), DISABLE, ON_CHANGE_ONLY)?
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => {
                    driver.monitor.debug_exceptions(DISABLE, SYNC)?
                }
                ExceptionVector::Breakpoint => driver.monitor.software_breakpoint(DISABLE)?,
                _ => return Err(XenDriverError::NotSupported),
            },
            EventMonitor::Singlestep => {
                for vcpu in 0..=driver.info.max_vcpu_id {
                    let _ = driver.domain.debug_control(vcpu.into(), 0);
                }

                driver.monitor.singlestep(DISABLE)?;
            }
            EventMonitor::Hypercall { .. } => driver.monitor.guest_request(DISABLE, SYNC, false)?,
            EventMonitor::CpuId => driver.monitor.cpuid(DISABLE)?,
            EventMonitor::Io => driver.monitor.io(DISABLE)?,
        }

        Ok(())
    }

    fn inject_interrupt(
        driver: &XenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), XenDriverError> {
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
    ) -> Result<(), XenDriverError> {
        // Convert the Xen event to a VMI event.
        let vmi_reason = match EventReason::try_from_ext(&event.reason) {
            Ok(reason) => reason,
            Err(_) => return Err(XenDriverError::NotSupported),
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

        match vmi_response.action {
            VmiEventAction::Continue => {}

            VmiEventAction::Deny => {
                event.flags |= VmEventFlag::DENY;
            }

            VmiEventAction::ReinjectInterrupt => match vmi_event.reason() {
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
            },

            // The VMI Singlestep action has one-shot semantics ("step one
            // instruction"), but Xen singlestep is a sticky toggle that
            // stays enabled until explicitly flipped off. We bridge the
            // two by toggling whenever the requested state differs from
            // the current one.
            //
            //   event        | action      | Xen toggle
            //   ------------ | ----------- | ----------
            //   non-SS       | Singlestep  | ON  (start stepping)
            //   singlestep   | Singlestep  | -   (continue, already on)
            //   singlestep   | other       | OFF (done stepping)
            //   non-SS       | other       | -   (leave as-is)
            VmiEventAction::Singlestep => {
                if !matches!(vmi_event.reason(), EventReason::Singlestep(_)) {
                    event.flags |= VmEventFlag::TOGGLE_SINGLESTEP;
                }
            }

            // Xen fast singlestep executes one instruction in the view
            // set by ALTERNATE_P2M (from vmi_response.view above), then
            // silently switches the vCPU to p2midx and auto-disables
            // singlestep - no VM event is generated.
            //
            // p2midx is the view to RETURN TO after the singlestep, not
            // the view to execute in. We use the incoming event's view so
            // the vCPU returns to whichever view triggered the original
            // event.
            VmiEventAction::FastSinglestep => {
                event.flags |= VmEventFlag::FAST_SINGLESTEP;
                event.options = Some(VmEventFlagOptions {
                    fast_singlestep: Some(VmEventFastSinglestep {
                        p2midx: view.map(|v| v.0).unwrap_or(0),
                    }),
                });
            }

            VmiEventAction::Emulate => {
                event.flags |= VmEventFlag::EMULATE;
            }
        }

        // When the action is NOT Singlestep but we are responding to a
        // singlestep event, Xen singlestep must be toggled off.
        if vmi_response.action != VmiEventAction::Singlestep
            && matches!(vmi_event.reason(), EventReason::Singlestep(_))
        {
            event.flags |= VmEventFlag::TOGGLE_SINGLESTEP;
        }

        Ok(())
    }

    fn reset_state(driver: &XenDriver<Self>) -> Result<(), XenDriverError> {
        let _ = driver.monitor_disable(EventMonitor::Io);
        let _ = driver.monitor_disable(EventMonitor::CpuId);
        let _ = driver.monitor_disable(EventMonitor::Hypercall {
            allow_userspace: false,
        });
        let _ = driver.monitor_disable(EventMonitor::Singlestep);
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint));
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::DebugException));

        // Try to disable all known MSR events.
        // Unfortunately, Xen does not provide a way to disable all MSR events
        // at once, so if a user enabled some MSR events that we don't know
        // about, those may remain enabled after reset.
        //
        // TODO: Track which MSR events have been enabled?
        {
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::TSC_AUX));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::KERNEL_GS_BASE));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::GS_BASE));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::FS_BASE));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::FMASK));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::CSTAR));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::LSTAR));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::STAR));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::EFER));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::SYSENTER_EIP));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::SYSENTER_ESP));
            let _ = driver.monitor_disable(EventMonitor::Msr(Msr::SYSENTER_CS));
        }

        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Xcr0));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr4));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr3));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr0));
        let _ = driver.altp2m.reset_view();
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
