//! Amd64 `ArchAdapter` implementation for the KVM driver.

mod event;
mod registers;

use std::{
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

use kvm::{
    KvmResponseAction, KvmVmiEvent, KvmVmiRegs, KvmVmiResponse,
    arch::x86::{KvmControl, KvmCr, KvmInjectEvent, KvmInjectType, KvmVmiRegsX86},
};
use vmi_arch_amd64::{
    Amd64, ControlRegister, EventMonitor, ExceptionVector, InterruptType, Msr, Registers,
};
use vmi_core::{
    Registers as _, VcpuId, View, VmiError, VmiEvent, VmiEventAction, VmiEventFlags,
    VmiEventResponse,
};

use crate::{ArchAdapter, FromExt as _, KvmVmiRing, ViewId, VmiKvmDriver};

/// Creates a non-blocking eventfd for ring signaling.
fn eventfd() -> Result<OwnedFd, VmiError> {
    // SAFETY: eventfd2 with a valid flag set returns a fresh fd or -1.
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(VmiError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a fresh, owned, valid file descriptor.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

/// Lazily sets up an event ring for every vCPU on first monitor enable.
fn ensure_rings(driver: &VmiKvmDriver<Amd64>) -> Result<(), VmiError> {
    let mut rings = driver.rings.borrow_mut();
    for (vcpu_id, slot) in rings.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }

        let event_fd = eventfd()?;
        let ack_fd = eventfd()?;
        let ring_fd = driver
            .session
            .setup_ring(vcpu_id as u32, event_fd.as_raw_fd(), ack_fd.as_raw_fd())
            .map_err(VmiError::driver)?;
        let ring =
            KvmVmiRing::new(vcpu_id as u32, ring_fd, event_fd, ack_fd).map_err(VmiError::driver)?;
        *slot = Some(ring);
    }
    Ok(())
}

/// Maps a `ControlRegister` to the native `KvmCr` enum.
fn cr_to_kvm(register: ControlRegister) -> KvmCr {
    match register {
        ControlRegister::Cr0 => KvmCr::Cr0,
        ControlRegister::Cr3 => KvmCr::Cr3,
        ControlRegister::Cr4 => KvmCr::Cr4,
        ControlRegister::Xcr0 => KvmCr::Xcr0,
    }
}

/// Maps an `InterruptType` to the native `KvmInjectType` enum.
fn interrupt_type_to_kvm(typ: InterruptType) -> KvmInjectType {
    match typ {
        InterruptType::ExternalInterrupt => KvmInjectType::ExtInt,
        InterruptType::Nmi => KvmInjectType::Nmi,
        InterruptType::HardwareException => KvmInjectType::HwExcept,
        InterruptType::SoftwareInterrupt => KvmInjectType::SwInt,
        InterruptType::PrivilegedSoftwareException => KvmInjectType::PrivSwInt,
        InterruptType::SoftwareException => KvmInjectType::SwExcept,
        // VMCS interruption type 1 (Reserved) cannot be injected; fall back to
        // a hardware exception.
        InterruptType::Reserved => KvmInjectType::HwExcept,
    }
}

/// Translates a monitor option into a native `KvmControl`.
fn control_from_option(option: EventMonitor) -> Result<KvmControl, VmiError> {
    match option {
        EventMonitor::Register(register) => Ok(KvmControl::Cr {
            reg: cr_to_kvm(register),
            on_change_only: true,
        }),
        EventMonitor::Msr(msr) => Ok(KvmControl::Msr(msr.0)),
        EventMonitor::CpuId => Ok(KvmControl::CpuId),
        EventMonitor::Io => Ok(KvmControl::Io),
        EventMonitor::Interrupt(vector) => match vector {
            ExceptionVector::Breakpoint => Ok(KvmControl::Breakpoint),
            ExceptionVector::DebugException => Ok(KvmControl::Debug),
            _ => Err(VmiError::NotSupported),
        },
        EventMonitor::Singlestep => Ok(KvmControl::Singlestep),
        EventMonitor::Hypercall { .. } => Ok(KvmControl::Hypercall),
    }
}

/// Translates a VMI response into a native `KvmVmiResponse`. When the handler
/// overrides registers, this reconstructs the full register set from the
/// in-event snapshot, applies the new GP registers, and packs it back.
fn build_response(event: &KvmVmiEvent, response: VmiEventResponse<Amd64>) -> KvmVmiResponse {
    let action = match response.action {
        VmiEventAction::Continue => KvmResponseAction::Continue,
        VmiEventAction::Deny => KvmResponseAction::Deny,
        VmiEventAction::Emulate => KvmResponseAction::Emulate,
        VmiEventAction::ReinjectInterrupt => KvmResponseAction::Reinject,
        VmiEventAction::Singlestep => KvmResponseAction::Singlestep,
        VmiEventAction::FastSinglestep => KvmResponseAction::FastSinglestep,
    };

    let regs = response.registers.map(|new_registers| {
        let KvmVmiRegs::X86(in_event) = event.regs;
        let mut full = Registers::from_ext(&in_event);
        full.set_gp_registers(&new_registers);
        KvmVmiRegs::X86(KvmVmiRegsX86::from_ext(&full))
    });

    KvmVmiResponse {
        action,
        regs,
        view_id: response.view.map(|view| u32::from(view.0)),
    }
}

impl ArchAdapter for Amd64 {
    fn registers(driver: &VmiKvmDriver<Self>, vcpu: VcpuId) -> Result<Registers, VmiError> {
        let kvcpu = match driver.vcpus.get(usize::from(vcpu.0)) {
            Some(kvcpu) => kvcpu,
            None => return Err(VmiError::NotSupported),
        };

        let regs = kvcpu.get_registers().map_err(VmiError::driver)?;
        Ok(Registers::from_ext(regs))
    }

    fn set_registers(
        driver: &VmiKvmDriver<Self>,
        vcpu: VcpuId,
        registers: Registers,
    ) -> Result<(), VmiError> {
        let kvcpu = match driver.vcpus.get(usize::from(vcpu.0)) {
            Some(kvcpu) => kvcpu,
            None => return Err(VmiError::NotSupported),
        };

        let regs = kvm::arch::x86::Registers::from_ext(&registers);
        kvcpu.set_registers(&regs).map_err(VmiError::driver)
    }

    fn monitor_enable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        ensure_rings(driver)?;
        let control = control_from_option(option)?;
        driver
            .session
            .control_event(control, true)
            .map_err(VmiError::driver)
    }

    fn monitor_disable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        let control = control_from_option(option)?;
        driver
            .session
            .control_event(control, false)
            .map_err(VmiError::driver)
    }

    fn inject_interrupt(
        driver: &VmiKvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), VmiError> {
        let arg = KvmInjectEvent {
            vcpu_id: u32::from(vcpu.0),
            vector: interrupt.vector.0,
            type_: interrupt_type_to_kvm(interrupt.typ),
            insn_len: interrupt.instruction_length,
            error_code: (interrupt.error_code != 0xffff_ffff).then_some(interrupt.error_code),
            cr2: interrupt.extra,
        };
        driver.session.inject_event(arg).map_err(VmiError::driver)
    }

    fn process_event(
        driver: &VmiKvmDriver<Self>,
        timeout: Duration,
        mut handler: impl FnMut(&VmiEvent<Self>) -> VmiEventResponse<Self>,
    ) -> Result<(), VmiError> {
        let timeout = timeout
            .as_millis()
            .try_into()
            .map_err(|_| VmiError::InvalidTimeout)?;

        // Snapshot the (vcpu_id, event_fd) pairs of the live rings under a
        // short borrow. The poll and the subsequent drain run with no rings
        // borrow held, so the handler may freely re-enter the driver.
        let mut fds = driver
            .rings
            .borrow()
            .iter()
            .filter_map(|ring| ring.as_ref())
            .map(|ring| libc::pollfd {
                fd: ring.event_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();

        if fds.is_empty() {
            return Err(VmiError::Timeout);
        }

        // SAFETY: fds is a valid, non-empty slice of pollfd.
        let poll_result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        match poll_result {
            0 => return Err(VmiError::Timeout),
            -1 => return Err(VmiError::Io(std::io::Error::last_os_error())),
            _ => {}
        }

        // The event_fds are level-triggered, so a fd that the kernel signaled
        // stays readable until its counter is drained. Read 8 bytes off each
        // ready fd to reset it before draining the ring, otherwise every later
        // poll returns immediately and the loop busy-spins.
        for pfd in &fds {
            if pfd.revents & libc::POLLIN != 0 {
                drain_eventfd(pfd.fd);
            }
        }

        let start = Instant::now();
        let result = process_ready_rings(driver, &mut handler);
        *driver.event_processing_overhead.borrow_mut() += start.elapsed();
        result
    }

    fn reset_state(driver: &VmiKvmDriver<Self>) -> Result<(), VmiError> {
        let _ = Self::monitor_disable(driver, EventMonitor::Io);
        let _ = Self::monitor_disable(driver, EventMonitor::CpuId);
        let _ = Self::monitor_disable(
            driver,
            EventMonitor::Hypercall {
                allow_userspace: false,
            },
        );
        let _ = Self::monitor_disable(driver, EventMonitor::Singlestep);
        let _ = Self::monitor_disable(driver, EventMonitor::Interrupt(ExceptionVector::Breakpoint));
        let _ = Self::monitor_disable(
            driver,
            EventMonitor::Interrupt(ExceptionVector::DebugException),
        );

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
            let _ = Self::monitor_disable(driver, EventMonitor::Msr(msr));
        }

        let _ = Self::monitor_disable(driver, EventMonitor::Register(ControlRegister::Xcr0));
        let _ = Self::monitor_disable(driver, EventMonitor::Register(ControlRegister::Cr4));
        let _ = Self::monitor_disable(driver, EventMonitor::Register(ControlRegister::Cr3));
        let _ = Self::monitor_disable(driver, EventMonitor::Register(ControlRegister::Cr0));

        let _ = driver.session.switch_view(ViewId(0));
        for view_id in driver.views.borrow().iter().copied().collect::<Vec<_>>() {
            let _ = driver.session.destroy_view(ViewId(view_id));
        }
        driver.views.borrow_mut().clear();

        Ok(())
    }
}

/// Drains 8 bytes off a level-triggered eventfd to reset its counter.
fn drain_eventfd(fd: std::os::fd::RawFd) {
    let mut buf = 0u64;
    // SAFETY: the eventfds are EFD_NONBLOCK, so this read never blocks. A
    // successful read returns 8 bytes and clears the counter, EAGAIN means
    // the counter was already zero. Either way the value is discarded.
    unsafe {
        libc::read(fd, &mut buf as *mut u64 as *mut libc::c_void, 8);
    }
}

/// Drains every ready ring, invoking the handler and acking each event. No
/// `rings` borrow is held while the handler runs, so the handler may call back
/// into the driver (for example `events_pending` or `wait_for_event`) without
/// tripping a `RefCell` double-borrow.
fn process_ready_rings(
    driver: &VmiKvmDriver<Amd64>,
    handler: &mut impl FnMut(&VmiEvent<Amd64>) -> VmiEventResponse<Amd64>,
) -> Result<(), VmiError> {
    let ring_count = driver.rings.borrow().len();

    for ring_index in 0..ring_count {
        loop {
            // Short borrow: peek+decode the next event, release the borrow
            // before the handler so it may re-enter the driver.
            let event = match driver
                .rings
                .borrow()
                .get(ring_index)
                .and_then(|ring| ring.as_ref())
            {
                Some(ring) => match ring.next_event() {
                    Some(event) => event,
                    None => break,
                },
                None => break,
            };

            let vcpu_id = event.vcpu_id;
            let registers = Registers::from_ext(&event);
            let view = match event.view_id {
                0 => None,
                view_id => Some(View(view_id as u16)),
            };
            let reason = event::reason_from_event(&event)?;
            let vmi_event = VmiEvent::new(
                VcpuId(vcpu_id as u16),
                VmiEventFlags::default(),
                view,
                registers,
                reason,
            );

            let response = handler(&vmi_event);
            let resp = build_response(&event, response);

            if let Some(Some(ring)) = driver.rings.borrow_mut().get_mut(ring_index) {
                ring.respond(resp);
            }
            driver
                .session
                .ack_event(vcpu_id)
                .map_err(VmiError::driver)?;
            if let Some(Some(ring)) = driver.rings.borrow_mut().get_mut(ring_index) {
                ring.advance();
            }
        }
    }
    Ok(())
}
