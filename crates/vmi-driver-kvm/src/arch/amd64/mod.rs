mod event;
mod registers;

use vmi_arch_amd64::{
    Amd64, ControlRegister, EventMonitor, EventReason, ExceptionVector, Interrupt,
};
use vmi_core::{
    Registers as _, VcpuId, View, VmiEvent, VmiEventFlags, VmiEventResponse,
    VmiEventResponseFlags,
};

use crate::{ArchAdapter, Error, IntoExt as _, KvmDriver, TryFromExt};

use self::event::{cr_to_index, interrupt_type_to_kvm};

/// Build a `kvm_vmi_control_event` for a simple event (no param union).
fn make_ctrl(vcpu_id: u32, event: u32, enable: u32) -> kvm::sys::kvm_vmi_control_event {
    kvm::sys::kvm_vmi_control_event {
        vcpu_id,
        event,
        enable,
        flags: 0,
        __bindgen_anon_1: kvm::sys::kvm_vmi_control_event__bindgen_ty_1::default(),
    }
}

/// Build a `kvm_vmi_control_event` for a CR event.
fn make_cr_ctrl(
    vcpu_id: u32,
    enable: u32,
    index: u8,
) -> kvm::sys::kvm_vmi_control_event {
    kvm::sys::kvm_vmi_control_event {
        vcpu_id,
        event: kvm::sys::KVM_VMI_EVENT_CR,
        enable,
        flags: 0,
        __bindgen_anon_1: kvm::sys::kvm_vmi_control_event__bindgen_ty_1 {
            cr: kvm::sys::kvm_vmi_control_event__bindgen_ty_1__bindgen_ty_1 {
                index,
                onchangeonly: 1,
                pad: [0; 6],
                bitmask: 0,
            },
        },
    }
}

impl ArchAdapter for Amd64 {
    fn registers_from_ring(regs: &kvm::sys::kvm_vmi_regs) -> Self::Registers {
        regs.into_ext()
    }

    fn registers_to_ring(regs: &Self::Registers) -> kvm::sys::kvm_vmi_regs {
        regs.into_ext()
    }

    fn monitor_enable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 1u32;

        match option {
            EventMonitor::Register(cr) => {
                let index = cr_to_index(cr);
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_cr_ctrl(vcpu_id, enable, index);
                    driver.monitor.control_event(&ctrl)?;
                }
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::Breakpoint => {
                    for vcpu_id in 0..driver.num_vcpus {
                        let ctrl =
                            make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_BREAKPOINT, enable);
                        driver.monitor.control_event(&ctrl)?;
                    }
                }
                ExceptionVector::DebugException => {
                    for vcpu_id in 0..driver.num_vcpus {
                        let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_DEBUG, enable);
                        driver.monitor.control_event(&ctrl)?;
                    }
                }
                _ => return Err(Error::NotSupported),
            },
            EventMonitor::Singlestep => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable);
                    driver.monitor.control_event(&ctrl)?;
                }
            }
            EventMonitor::CpuId => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_CPUID, enable);
                    driver.monitor.control_event(&ctrl)?;
                }
            }
            EventMonitor::Io => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_IO, enable);
                    driver.monitor.control_event(&ctrl)?;
                }
            }
            EventMonitor::GuestRequest { .. } => {
                // KVM has no VMCALL event.
                return Err(Error::NotSupported);
            }
        }

        Ok(())
    }

    fn monitor_disable(driver: &KvmDriver<Self>, option: Self::EventMonitor) -> Result<(), Error> {
        let enable = 0u32;

        match option {
            EventMonitor::Register(cr) => {
                let index = cr_to_index(cr);
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_cr_ctrl(vcpu_id, enable, index);
                    let _ = driver.monitor.control_event(&ctrl);
                }
            }
            EventMonitor::Interrupt(vector) => match vector {
                ExceptionVector::Breakpoint => {
                    for vcpu_id in 0..driver.num_vcpus {
                        let ctrl =
                            make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_BREAKPOINT, enable);
                        let _ = driver.monitor.control_event(&ctrl);
                    }
                }
                ExceptionVector::DebugException => {
                    for vcpu_id in 0..driver.num_vcpus {
                        let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_DEBUG, enable);
                        let _ = driver.monitor.control_event(&ctrl);
                    }
                }
                _ => return Err(Error::NotSupported),
            },
            EventMonitor::Singlestep => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_SINGLESTEP, enable);
                    let _ = driver.monitor.control_event(&ctrl);
                }
            }
            EventMonitor::CpuId => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_CPUID, enable);
                    let _ = driver.monitor.control_event(&ctrl);
                }
            }
            EventMonitor::Io => {
                for vcpu_id in 0..driver.num_vcpus {
                    let ctrl = make_ctrl(vcpu_id, kvm::sys::KVM_VMI_EVENT_IO, enable);
                    let _ = driver.monitor.control_event(&ctrl);
                }
            }
            EventMonitor::GuestRequest { .. } => {
                // KVM has no VMCALL event.
                return Err(Error::NotSupported);
            }
        }

        Ok(())
    }

    fn inject_interrupt(
        driver: &KvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Interrupt,
    ) -> Result<(), Error> {
        let has_error = interrupt.error_code != 0xffff_ffff;
        Ok(driver.session.inject_event(
            u16::from(vcpu) as u32,
            interrupt.vector.0,
            interrupt_type_to_kvm(interrupt.typ),
            interrupt.error_code,
            has_error,
            interrupt.extra,
        )?)
    }

    fn process_event(
        _driver: &KvmDriver<Self>,
        raw_event: &mut kvm::sys::kvm_vmi_ring_event,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), Error> {
        // Parse the raw ring event into a safe event.
        let kvm_event =
            unsafe { kvm::KvmVmiEvent::from_raw(raw_event) }.ok_or(Error::NotSupported)?;

        // Convert to VMI event reason.
        let vmi_reason =
            EventReason::try_from_ext(&kvm_event.reason).map_err(|()| Error::NotSupported)?;

        // Convert registers.
        let mut registers = Self::registers_from_ring(&raw_event.regs);

        // Build the VMI event.
        let view = Some(View(kvm_event.view_id as u16));
        let flags = VmiEventFlags::VCPU_PAUSED; // vCPU is always paused during ring events
        let vcpu_id = VcpuId::from(kvm_event.vcpu_id as u16);

        let vmi_event = VmiEvent::new(vcpu_id, flags, view, registers, vmi_reason);

        // Call the user's handler.
        let vmi_response = handler(&vmi_event);

        // Build the ring response flags.
        let mut response_flags: u32 = kvm::sys::KVM_VMI_RESPONSE_ALLOW;

        // Handle SET_REGS.
        if let Some(new_gp_regs) = &vmi_response.registers {
            registers.set_gp_registers(new_gp_regs);
            raw_event.regs = Self::registers_to_ring(&registers);
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SET_REGS;
        }

        // Handle SWITCH_VIEW.
        if let Some(new_view) = vmi_response.view {
            raw_event.view_id = new_view.0 as u32;
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
        }

        // Handle TOGGLE_SINGLESTEP.
        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::TOGGLE_SINGLESTEP)
        {
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP;
        }

        // Handle TOGGLE_FAST_SINGLESTEP.
        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::TOGGLE_FAST_SINGLESTEP)
        {
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP_FAST;
        }

        // Handle EMULATE.
        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::EMULATE)
        {
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_EMULATE;
        }

        // Handle REINJECT_INTERRUPT.
        if vmi_response
            .flags
            .contains(VmiEventResponseFlags::REINJECT_INTERRUPT)
        {
            response_flags |= kvm::sys::KVM_VMI_RESPONSE_REINJECT;
        }

        raw_event.response = response_flags;

        Ok(())
    }

    fn reset_state(driver: &KvmDriver<Self>) -> Result<(), Error> {
        let _ = driver.monitor_disable(EventMonitor::Io);
        let _ = driver.monitor_disable(EventMonitor::CpuId);
        let _ = driver.monitor_disable(EventMonitor::Singlestep);
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::Breakpoint));
        let _ = driver.monitor_disable(EventMonitor::Interrupt(ExceptionVector::DebugException));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Xcr0));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr4));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr3));
        let _ = driver.monitor_disable(EventMonitor::Register(ControlRegister::Cr0));

        // Switch all vCPUs back to view 0.
        for vcpu_id in 0..driver.num_vcpus {
            let _ = driver.session.switch_view(vcpu_id, 0);
        }

        // Destroy all views.
        driver.views.borrow_mut().clear();

        Ok(())
    }
}
