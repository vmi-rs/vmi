mod event;
mod registers;

use vmi_arch_amd64::{Amd64, ControlRegister, EventMonitor, EventReason, ExceptionVector, Msr};
use vmi_core::{
    Registers as _, VcpuId, View, VmiError, VmiEvent, VmiEventAction, VmiEventFlags,
    VmiEventResponse, driver::VmiEventControl,
};
use xen::ctrl::{
    VmEvent, VmEventData, VmEventFastSinglestep, VmEventFlag, VmEventFlagOptions, VmEventRegs,
};

use crate::{ArchAdapter, IntoExt as _, TryFromExt as _, VmiXenDriver};

impl ArchAdapter for Amd64 {
    type XenArch = xen::arch::x86::Amd64;

    fn registers(driver: &VmiXenDriver<Self>, vcpu: VcpuId) -> Result<Self::Registers, VmiError> {
        Ok(driver
            .domain
            .get_context_cpu(vcpu.into_ext())
            .map_err(VmiError::driver)?
            .into_ext())
    }

    fn set_registers(
        driver: &VmiXenDriver<Self>,
        vcpu: VcpuId,
        registers: Self::Registers,
    ) -> Result<(), VmiError> {
        driver
            .domain
            .set_context_cpu(vcpu.into_ext(), registers.into_ext())
            .map_err(VmiError::driver)
    }

    fn monitor_enable(
        driver: &VmiXenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        const ENABLE: bool = true;
        const SYNC: bool = true;

        match option {
            EventMonitor::Register(monitor) => {
                driver
                    .monitor
                    .write_ctrlreg(
                        monitor.register.into_ext(),
                        ENABLE,
                        SYNC,
                        0,
                        monitor.on_change_only,
                    )
                    .map_err(VmiError::driver)?;
            }
            EventMonitor::Msr(monitor) => driver
                .monitor
                .mov_to_msr(monitor.msr.into(), ENABLE, monitor.on_change_only)
                .map_err(VmiError::driver)?,
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => driver
                    .monitor
                    .debug_exceptions(ENABLE, SYNC)
                    .map_err(VmiError::driver)?,
                ExceptionVector::Breakpoint => driver
                    .monitor
                    .software_breakpoint(ENABLE)
                    .map_err(VmiError::driver)?,
                _ => return Err(VmiError::NotSupported),
            },
            EventMonitor::Singlestep => driver
                .monitor
                .singlestep(ENABLE)
                .map_err(VmiError::driver)?,
            EventMonitor::Hypercall(monitor) => driver
                .monitor
                .guest_request(ENABLE, SYNC, monitor.allow_userspace)
                .map_err(VmiError::driver)?,
            EventMonitor::CpuId => driver.monitor.cpuid(ENABLE).map_err(VmiError::driver)?,
            EventMonitor::Io => driver.monitor.io(ENABLE).map_err(VmiError::driver)?,
        }

        Ok(())
    }

    fn monitor_disable(
        driver: &VmiXenDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        const DISABLE: bool = false;
        const SYNC: bool = true;

        match option {
            EventMonitor::Register(monitor) => {
                driver
                    .monitor
                    .write_ctrlreg(
                        monitor.register.into_ext(),
                        DISABLE,
                        SYNC,
                        0,
                        monitor.on_change_only,
                    )
                    .map_err(VmiError::driver)?;
            }
            EventMonitor::Msr(monitor) => driver
                .monitor
                .mov_to_msr(monitor.msr.into(), DISABLE, monitor.on_change_only)
                .map_err(VmiError::driver)?,
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::DebugException => driver
                    .monitor
                    .debug_exceptions(DISABLE, SYNC)
                    .map_err(VmiError::driver)?,
                ExceptionVector::Breakpoint => driver
                    .monitor
                    .software_breakpoint(DISABLE)
                    .map_err(VmiError::driver)?,
                _ => return Err(VmiError::NotSupported),
            },
            EventMonitor::Singlestep => {
                for vcpu in 0..=driver.info.max_vcpu_id {
                    let _ = driver.domain.debug_control(vcpu.into(), 0);
                }

                driver
                    .monitor
                    .singlestep(DISABLE)
                    .map_err(VmiError::driver)?;
            }
            EventMonitor::Hypercall(monitor) => driver
                .monitor
                .guest_request(DISABLE, SYNC, monitor.allow_userspace)
                .map_err(VmiError::driver)?,
            EventMonitor::CpuId => driver.monitor.cpuid(DISABLE).map_err(VmiError::driver)?,
            EventMonitor::Io => driver.monitor.io(DISABLE).map_err(VmiError::driver)?,
        }

        Ok(())
    }

    fn inject_interrupt(
        driver: &VmiXenDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), VmiError> {
        driver
            .devicemodel
            .inject_event(
                vcpu.into_ext(),
                interrupt.vector.into_ext(),
                interrupt.typ.into_ext(),
                interrupt.error_code,
                interrupt.instruction_length,
                interrupt.extra,
            )
            .map_err(VmiError::driver)
    }

    fn process_event(
        driver: &VmiXenDriver<Self>,
        event: &mut VmEvent,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), VmiError> {
        // Convert the Xen event to a VMI event.
        let vmi_reason = match EventReason::try_from_ext(&event.reason) {
            Ok(reason) => reason,
            Err(_) => return Err(VmiError::NotSupported),
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
                    driver
                        .devicemodel
                        .inject_event(
                            event.vcpu_id,
                            data.interrupt.vector.into_ext(),
                            data.interrupt.typ.into_ext(),
                            data.interrupt.error_code,
                            data.interrupt.instruction_length,
                            data.interrupt.extra,
                        )
                        .map_err(VmiError::driver)?;
                }
                _ => {
                    tracing::warn!(
                        "attempted to reinject interrupt when current event is not an interrupt"
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

    fn reset_state(driver: &VmiXenDriver<Self>) -> Result<(), VmiError> {
        let _ = driver.monitor_disable(EventMonitor::io());
        let _ = driver.monitor_disable(EventMonitor::cpuid());
        let _ = driver.monitor_disable(EventMonitor::hypercall().into());
        let _ = driver.monitor_disable(EventMonitor::singlestep());
        let _ = driver.monitor_disable(EventMonitor::interrupt(ExceptionVector::Breakpoint));
        let _ = driver.monitor_disable(EventMonitor::interrupt(ExceptionVector::DebugException));

        // Try to disable all known MSR events.
        // Unfortunately, Xen does not provide a way to disable all MSR events
        // at once, so if a user enabled some MSR events that we don't know
        // about, those may remain enabled after reset.
        //
        // TODO: Track which MSR events have been enabled?
        for msr in [
            Msr::TSC_AUX,
            Msr::KERNEL_GS_BASE,
            Msr::GS_BASE,
            Msr::FS_BASE,
            Msr::FMASK,
            Msr::CSTAR,
            Msr::LSTAR,
            Msr::STAR,
            Msr::EFER,
            Msr::SYSENTER_EIP,
            Msr::SYSENTER_ESP,
            Msr::SYSENTER_CS,
        ] {
            let _ = driver.monitor_disable(EventMonitor::msr(msr).into());
        }

        for register in [
            ControlRegister::Xcr0,
            ControlRegister::Cr4,
            ControlRegister::Cr3,
            ControlRegister::Cr0,
        ] {
            let _ = driver.monitor_disable(EventMonitor::register(register).into());
        }

        let _ = driver.altp2m.reset_view();
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
