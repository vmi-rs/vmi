//! Amd64 `ArchAdapter` implementation for the KVM driver.

mod event;
mod registers;

use std::{
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

use vmi_arch_amd64::{
    Amd64, ControlRegister, EventMonitor, ExceptionVector, Interrupt, InterruptType, Msr, Registers,
};
use vmi_core::{
    Registers as _, VcpuId, View, VmiError, VmiEvent, VmiEventAction, VmiEventFlags,
    VmiEventResponse,
};

use self::registers::{KvmFullRegs, KvmMsrs};
use crate::{ArchAdapter, FromExt as _, KvmVcpu, KvmVmiRing, ViewId, VmiKvmDriver};

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

/// Reads the MSRs the driver tracks into a named bundle.
fn read_msrs(vcpu: &KvmVcpu) -> Result<KvmMsrs, VmiError> {
    let indices = [
        Msr::EFER,
        Msr::STAR,
        Msr::LSTAR,
        Msr::CSTAR,
        Msr::FMASK,
        Msr::KERNEL_GS_BASE,
        Msr::SYSENTER_CS,
        Msr::SYSENTER_ESP,
        Msr::SYSENTER_EIP,
        Msr::TSC_AUX,
    ];

    let mut entries = indices
        .iter()
        .map(|msr| kvm::sys::kvm_msr_entry {
            index: msr.0,
            ..Default::default()
        })
        .collect::<Vec<_>>();

    vcpu.get_msrs(&mut entries).map_err(VmiError::driver)?;

    Ok(KvmMsrs {
        efer: entries[0].data,
        star: entries[1].data,
        lstar: entries[2].data,
        cstar: entries[3].data,
        sfmask: entries[4].data,
        kernel_gs_base: entries[5].data,
        sysenter_cs: entries[6].data,
        sysenter_esp: entries[7].data,
        sysenter_eip: entries[8].data,
        tsc_aux: entries[9].data,
    })
}

/// Maps a control register to its KVM index.
fn control_register_index(register: ControlRegister) -> u32 {
    match register {
        ControlRegister::Cr0 => kvm::sys::KVM_VMI_CR0,
        ControlRegister::Cr3 => kvm::sys::KVM_VMI_CR3,
        ControlRegister::Cr4 => kvm::sys::KVM_VMI_CR4,
        ControlRegister::Xcr0 => kvm::sys::KVM_VMI_XCR0,
    }
}

/// Translates a monitor option into a KVM event id and its arch control data.
fn control_args(
    option: EventMonitor,
) -> Result<(u32, kvm::sys::kvm_vmi_arch_control_data), VmiError> {
    let mut arch = kvm::sys::kvm_vmi_arch_control_data::default();

    match option {
        EventMonitor::Register(register) => {
            arch.cr.index = control_register_index(register) as u8;
            arch.cr.onchangeonly = 1;
            Ok((kvm::sys::KVM_VMI_EVENT_CR, arch))
        }
        EventMonitor::Msr(msr) => {
            arch.msr.msr = msr.0;
            Ok((kvm::sys::KVM_VMI_EVENT_MSR, arch))
        }
        EventMonitor::CpuId => Ok((kvm::sys::KVM_VMI_EVENT_CPUID, arch)),
        EventMonitor::Io => Ok((kvm::sys::KVM_VMI_EVENT_IO, arch)),
        EventMonitor::Interrupt(vector) => match vector {
            ExceptionVector::Breakpoint => Ok((kvm::sys::KVM_VMI_EVENT_BREAKPOINT, arch)),
            ExceptionVector::DebugException => Ok((kvm::sys::KVM_VMI_EVENT_DEBUG, arch)),
            _ => Err(VmiError::NotSupported),
        },
        EventMonitor::Singlestep => Ok((kvm::sys::KVM_VMI_EVENT_SINGLESTEP, arch)),
        EventMonitor::Hypercall { .. } => Ok((kvm::sys::KVM_VMI_EVENT_HYPERCALL, arch)),
    }
}

/// Maps an amd64 interrupt type to the KVM injection type encoding.
fn inject_type(typ: InterruptType) -> u8 {
    let value = match typ {
        InterruptType::ExternalInterrupt => kvm::sys::KVM_VMI_EVENT_TYPE_EXT_INT,
        InterruptType::Nmi => kvm::sys::KVM_VMI_EVENT_TYPE_NMI,
        InterruptType::HardwareException => kvm::sys::KVM_VMI_EVENT_TYPE_HW_EXCEPT,
        InterruptType::SoftwareInterrupt => kvm::sys::KVM_VMI_EVENT_TYPE_SW_INT,
        InterruptType::PrivilegedSoftwareException => kvm::sys::KVM_VMI_EVENT_TYPE_PRIV_SW_INT,
        InterruptType::SoftwareException => kvm::sys::KVM_VMI_EVENT_TYPE_SW_EXCEPT,
        InterruptType::Reserved => kvm::sys::KVM_VMI_EVENT_TYPE_HW_EXCEPT,
    };
    value as u8
}

/// Builds a KVM inject-event argument from an amd64 interrupt.
fn inject_event_arg(vcpu: VcpuId, interrupt: Interrupt) -> kvm::sys::kvm_vmi_inject_event {
    let has_error = u32::from(interrupt.error_code != 0xffff_ffff);
    kvm::sys::kvm_vmi_inject_event {
        vcpu_id: u32::from(vcpu.0),
        vector: interrupt.vector.0,
        type_: inject_type(interrupt.typ),
        insn_len: interrupt.instruction_length,
        pad: 0,
        error_code: if has_error == 1 {
            interrupt.error_code
        }
        else {
            0
        },
        has_error,
        cr2: interrupt.extra,
    }
}

/// Translates a VMI response into the KVM ring-slot response flags, writing
/// back registers and view as needed.
fn apply_response(slot: &mut kvm::sys::kvm_vmi_ring_event, response: VmiEventResponse<Amd64>) {
    let mut flags = kvm::sys::KVM_VMI_RESPONSE_CONTINUE;

    if let Some(new_registers) = response.registers {
        let mut registers = Registers::from_ext(&slot.regs);
        registers.set_gp_registers(&new_registers);
        slot.regs = kvm::sys::kvm_vmi_regs::from_ext(&registers);
        flags |= kvm::sys::KVM_VMI_RESPONSE_SET_REGS;
    }

    if let Some(view) = response.view {
        slot.view_id = u32::from(view.0);
        flags |= kvm::sys::KVM_VMI_RESPONSE_SWITCH_VIEW;
    }

    match response.action {
        VmiEventAction::Continue => {}
        VmiEventAction::Deny => flags |= kvm::sys::KVM_VMI_RESPONSE_DENY,
        VmiEventAction::Emulate => flags |= kvm::sys::KVM_VMI_RESPONSE_EMULATE,
        VmiEventAction::ReinjectInterrupt => flags |= kvm::sys::KVM_VMI_RESPONSE_REINJECT,
        VmiEventAction::Singlestep => flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP,
        VmiEventAction::FastSinglestep => flags |= kvm::sys::KVM_VMI_RESPONSE_SINGLESTEP_FAST,
    }

    slot.response = flags;
}

impl ArchAdapter for Amd64 {
    fn registers(driver: &VmiKvmDriver<Self>, vcpu: VcpuId) -> Result<Registers, VmiError> {
        let kvcpu = match driver.vcpus.get(usize::from(vcpu.0)) {
            Some(kvcpu) => kvcpu,
            None => return Err(VmiError::NotSupported),
        };

        let regs = kvcpu.get_regs().map_err(VmiError::driver)?;
        let sregs = kvcpu.get_sregs().map_err(VmiError::driver)?;
        let debugregs = kvcpu.get_debugregs().map_err(VmiError::driver)?;
        let msrs = read_msrs(kvcpu)?;

        Ok(Registers::from_ext(KvmFullRegs {
            regs,
            sregs,
            debugregs,
            msrs,
        }))
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

        let regs = kvm::sys::kvm_regs::from_ext(&registers);
        let sregs = kvm::sys::kvm_sregs::from_ext(&registers);
        kvcpu.set_regs(&regs).map_err(VmiError::driver)?;
        kvcpu.set_sregs(&sregs).map_err(VmiError::driver)?;
        Ok(())
    }

    fn monitor_enable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        ensure_rings(driver)?;
        let (event, arch) = control_args(option)?;
        driver
            .session
            .control_event(event, true, arch)
            .map_err(VmiError::driver)
    }

    fn monitor_disable(
        driver: &VmiKvmDriver<Self>,
        option: Self::EventMonitor,
    ) -> Result<(), VmiError> {
        let (event, arch) = control_args(option)?;
        driver
            .session
            .control_event(event, false, arch)
            .map_err(VmiError::driver)
    }

    fn inject_interrupt(
        driver: &VmiKvmDriver<Self>,
        vcpu: VcpuId,
        interrupt: Self::Interrupt,
    ) -> Result<(), VmiError> {
        let arg = inject_event_arg(vcpu, interrupt);
        driver.session.inject_event(&arg).map_err(VmiError::driver)
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

/// Returns the current slot pointer and vcpu id for `ring_index`, or `None`
/// when that ring has no queued event. The `rings` borrow is released on
/// return. The raw pointer stays valid because it points into the mmap region
/// owned by the `KvmVmiRing`, and the backing `Vec` is not mutated during
/// event processing, so the pointer outlives the borrow and the handler may
/// re-enter the driver.
fn next_ready_slot(
    driver: &VmiKvmDriver<Amd64>,
    ring_index: usize,
) -> Option<(*mut kvm::sys::kvm_vmi_ring_event, u32)> {
    let mut rings = driver.rings.borrow_mut();
    let ring = rings.get_mut(ring_index)?.as_mut()?;
    let slot_ptr = ring.current_slot()?;
    Some((slot_ptr, ring.vcpu_id()))
}

/// Advances the consumer cursor of `ring_index` under a short borrow.
fn advance_ring(driver: &VmiKvmDriver<Amd64>, ring_index: usize) {
    let mut rings = driver.rings.borrow_mut();
    if let Some(Some(ring)) = rings.get_mut(ring_index) {
        ring.advance();
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
        // Drain every queued slot for this ring. Each iteration takes a short
        // borrow to fetch the slot pointer, releases it, then runs the handler
        // and applies the response with no borrow held.
        while let Some((slot_ptr, vcpu_id)) = next_ready_slot(driver, ring_index) {
            // SAFETY: slot_ptr points into the mapped ring page and stays
            // valid until the slot is acked. The Vec backing the rings is not
            // mutated while this pointer is live, so the mmap stays mapped.
            let slot = unsafe { &mut *slot_ptr };

            let reason = event::reason_from_slot(slot)?;

            let registers = Registers::from_ext(&slot.regs);
            let view = match slot.view_id {
                0 => None,
                view_id => Some(View(view_id as u16)),
            };
            let flags = VmiEventFlags::default();

            let vmi_event = VmiEvent::new(VcpuId(vcpu_id as u16), flags, view, registers, reason);

            let response = handler(&vmi_event);

            // SAFETY: same slot pointer, still valid until the ack below.
            apply_response(unsafe { &mut *slot_ptr }, response);

            driver
                .session
                .ack_event(vcpu_id)
                .map_err(VmiError::driver)?;
            advance_ring(driver, ring_index);
        }
    }
    Ok(())
}
