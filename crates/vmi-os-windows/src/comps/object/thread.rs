use vmi_core::{
    Architecture, Va, VcpuId, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{ProcessObject, ThreadId, ThreadObject, VmiOsProcess as _, VmiOsThread},
};

use super::{
    super::{WindowsProcessorMode, WindowsTeb, WindowsTrapFrame, WindowsWow64Kind},
    FromWindowsObject, WindowsObject, WindowsObjectTypeKind, WindowsProcess, WindowsToken,
};
use crate::{ArchAdapter, WindowsOs, WindowsOsExt as _, offset};

/// Windows kernel thread state (`KTHREAD_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsThreadState {
    /// Thread has been initialized but not yet started.
    Initialized,
    /// Thread is ready to run.
    Ready,
    /// Thread is currently running.
    Running,
    /// Thread is selected to run next on a processor.
    Standby,
    /// Thread has terminated.
    Terminated,
    /// Thread is waiting for an event.
    Waiting,
    /// Thread is transitioning between states.
    Transition,
    /// Thread is ready to run but deferred.
    DeferredReady,
    /// Obsolete gate wait state.
    GateWaitObsolete,
    /// Thread is waiting for process in swap.
    WaitingForProcessInSwap,
    /// Unknown state value not covered by known variants.
    Unknown(u8),
}

impl From<u8> for WindowsThreadState {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Initialized,
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Standby,
            4 => Self::Terminated,
            5 => Self::Waiting,
            6 => Self::Transition,
            7 => Self::DeferredReady,
            8 => Self::GateWaitObsolete,
            9 => Self::WaitingForProcessInSwap,
            other => Self::Unknown(other),
        }
    }
}

/// Windows thread wait reason (`KWAIT_REASON`).
///
/// The unprefixed variants `Executive`..`UserRequest` are the kernel's own
/// waits. Their `Wr`-prefixed duals `WrExecutive`..`WrUserRequest` are the
/// same waits performed on behalf of user mode, set when
/// `KeWaitForSingleObject` is called with `WaitMode = UserMode`. Variants past
/// `WrUserRequest` identify specific subsystems such as LPC, MM, scheduler,
/// and locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsThreadWaitReason {
    /// Kernel-initiated generic synchronization wait on an executive object.
    Executive,
    /// Waiting for a free page in the zero/free page lists.
    FreePage,
    /// Waiting for an in-progress hard-fault page read to complete.
    PageIn,
    /// Waiting for paged or nonpaged pool to have memory available.
    PoolAllocation,
    /// Self-initiated sleep via `KeDelayExecutionThread`.
    DelayExecution,
    /// Thread is suspended via `NtSuspendThread` or an APC.
    Suspended,
    /// User-mode wait issued by a routine such as `WaitForSingleObject`.
    UserRequest,

    /// Waiting on an executive object on behalf of user mode.
    WrExecutive,
    /// User-mode free-page wait, typically for paging.
    WrFreePage,
    /// Hard page-in wait on behalf of user mode.
    WrPageIn,
    /// Pool-allocation wait on behalf of user mode.
    WrPoolAllocation,
    /// User-mode delayed execution via `NtDelayExecution`.
    WrDelayExecution,
    /// User-mode thread suspension.
    WrSuspended,
    /// Alertable user-mode wait on an object.
    WrUserRequest,
    /// Waiting on an LPC event pair for a paired client/server handshake.
    WrEventPair,
    /// Waiting for a `KQUEUE` entry used by I/O completion and worker
    /// threads.
    WrQueue,
    /// LPC server waiting to receive a message from a client.
    WrLpcReceive,
    /// LPC client waiting for a reply from the server.
    WrLpcReply,
    /// Waiting on a virtual-memory operation that mutates the address space.
    WrVirtualMemory,
    /// Waiting for modified-page writer to complete a page-out.
    WrPageOut,
    /// Waiting at a rendezvous point for another thread/processor.
    WrRendezvous,
    /// Waiting on a keyed event, used by critical sections.
    WrKeyedEvent,
    /// Thread has terminated. Wait is for teardown bookkeeping.
    WrTerminated,
    /// Waiting for the process to be swapped back into memory.
    WrProcessInSwap,
    /// Blocked by CPU rate-control / job CPU throttling.
    WrCpuRateControl,
    /// Waiting on a user-mode stack-switch callout.
    WrCalloutStack,
    /// Generic in-kernel wait not covered by a specific reason.
    WrKernel,
    /// Contending for an `ERESOURCE` executive resource.
    WrResource,
    /// Contending for an `EX_PUSH_LOCK`.
    WrPushLock,
    /// Waiting to acquire a `KMUTEX` / `KMUTANT`.
    WrMutex,
    /// Quantum has ended. Rescheduled pending context switch.
    WrQuantumEnd,
    /// Awaiting a dispatch interrupt to run the scheduler.
    WrDispatchInt,
    /// Preempted by a higher-priority thread.
    WrPreempted,
    /// Voluntarily yielded CPU via `NtYieldExecution`.
    WrYieldExecution,
    /// Contending for a `FAST_MUTEX`.
    WrFastMutex,
    /// Contending for a `KGUARDED_MUTEX`.
    WrGuardedMutex,
    /// Blocked on an `EX_RUNDOWN_REF` rundown-protection drain.
    WrRundown,
    /// Blocked on `NtWaitForAlertByThreadId` / thread-ID alert.
    WrAlertByThreadId,
    /// Preemption deferred pending a scheduler decision.
    WrDeferredPreempt,
    /// Waiting to service a hardware/physical memory fault.
    WrPhysicalFault,
    /// Blocked on an I/O ring submission/completion.
    WrIoRing,
    /// Waiting for an MDL cache slot to become available.
    WrMdlCache,
    /// Blocked inside an RCU grace period.
    WrRcu,

    /// Unknown wait reason value not covered by known variants.
    Unknown(u8),
}

impl From<u8> for WindowsThreadWaitReason {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Executive,
            1 => Self::FreePage,
            2 => Self::PageIn,
            3 => Self::PoolAllocation,
            4 => Self::DelayExecution,
            5 => Self::Suspended,
            6 => Self::UserRequest,
            7 => Self::WrExecutive,
            8 => Self::WrFreePage,
            9 => Self::WrPageIn,
            10 => Self::WrPoolAllocation,
            11 => Self::WrDelayExecution,
            12 => Self::WrSuspended,
            13 => Self::WrUserRequest,
            14 => Self::WrEventPair, // WrSpare0 since Windows 8.1
            15 => Self::WrQueue,
            16 => Self::WrLpcReceive,
            17 => Self::WrLpcReply,
            18 => Self::WrVirtualMemory,
            19 => Self::WrPageOut,
            20 => Self::WrRendezvous,
            21 => Self::WrKeyedEvent,
            22 => Self::WrTerminated,
            23 => Self::WrProcessInSwap,
            24 => Self::WrCpuRateControl,
            25 => Self::WrCalloutStack,
            26 => Self::WrKernel,
            27 => Self::WrResource,
            28 => Self::WrPushLock,
            29 => Self::WrMutex,
            30 => Self::WrQuantumEnd,
            31 => Self::WrDispatchInt,
            32 => Self::WrPreempted,
            33 => Self::WrYieldExecution,
            34 => Self::WrFastMutex,
            35 => Self::WrGuardedMutex,
            36 => Self::WrRundown,
            37 => Self::WrAlertByThreadId,
            38 => Self::WrDeferredPreempt,
            39 => Self::WrPhysicalFault,
            40 => Self::WrIoRing,
            41 => Self::WrMdlCache,
            42 => Self::WrRcu,
            other => Self::Unknown(other),
        }
    }
}

/// A Windows thread.
///
/// A thread in Windows is represented by the `_ETHREAD` structure,
/// which contains metadata about its execution state, context, and scheduling.
///
/// # Implementation Details
///
/// Corresponds to `_ETHREAD`.
pub struct WindowsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_ETHREAD` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsThread<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsThread<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        match object.type_kind()? {
            Some(WindowsObjectTypeKind::Thread) => {
                Ok(Some(Self::new(object.vmi, ThreadObject(object.va))))
            }
            _ => Ok(None),
        }
    }
}

impl<Driver> VmiVa for WindowsThread<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows thread.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, thread: ThreadObject) -> Self {
        Self { vmi, va: thread.0 }
    }

    /// Returns the process object associated with the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Process`.
    pub fn process(&self) -> Result<WindowsProcess<'a, Driver>, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let process = self
            .vmi
            .read_va_native(self.va + KTHREAD.Process.offset())?;

        Ok(WindowsProcess::new(self.vmi, ProcessObject(process)))
    }

    /// Checks if the thread is currently attached to foreign process context.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.ApcStateIndex != 0`.
    pub fn is_attached(&self) -> Result<bool, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let apc_state_index = self.vmi.read_u8(self.va + KTHREAD.ApcStateIndex.offset())?;

        Ok(apc_state_index != 0)
    }

    /// Returns the process whose address space the thread is currently executing in.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.ApcState.Process`.
    pub fn current_process(&self) -> Result<WindowsProcess<'a, Driver>, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);
        let KAPC_STATE = offset!(self.vmi, _KAPC_STATE);

        let process = self
            .vmi
            .read_va_native(self.va + KTHREAD.ApcState.offset() + KAPC_STATE.Process.offset())?;

        Ok(WindowsProcess::new(self.vmi, ProcessObject(process)))
    }

    /// Returns the thread's saved home process, or NULL if the thread is not attached.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.SavedApcState.Process`.
    pub fn saved_process(&self) -> Result<Option<WindowsProcess<'a, Driver>>, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);
        let KAPC_STATE = offset!(self.vmi, _KAPC_STATE);

        let process = self.vmi.read_va_native(
            self.va + KTHREAD.SavedApcState.offset() + KAPC_STATE.Process.offset(),
        )?;

        if process.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsProcess::new(self.vmi, ProcessObject(process))))
    }

    /// Returns the thread's impersonation token, or `None` when the
    /// thread is not currently impersonating.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_ETHREAD.ClientSecurity.ImpersonationToken`, gated
    /// on `_ETHREAD.ActiveImpersonationInfo`.
    pub fn impersonation_token(&self) -> Result<Option<WindowsToken<'a, Driver>>, VmiError> {
        let ETHREAD = offset!(self.vmi, _ETHREAD);
        let PS_CLIENT_SECURITY_CONTEXT = offset!(self.vmi, _PS_CLIENT_SECURITY_CONTEXT);

        let active = self
            .vmi
            .read_field(self.va, &ETHREAD.ActiveImpersonationInfo)?;

        if ETHREAD.ActiveImpersonationInfo.extract(active) == 0 {
            return Ok(None);
        }

        let token = self.vmi.os().read_fast_ref(
            self.va
                + ETHREAD.ClientSecurity.offset()
                + PS_CLIENT_SECURITY_CONTEXT.ImpersonationToken.offset(),
        )?;

        Ok(Some(WindowsToken::new(self.vmi, token)))
    }

    /// Returns the ID of the processor the thread is bound to.
    ///
    /// For a [`Running`] thread this is the CPU currently executing it.
    /// For a [`Ready`] or [`Standby`] thread this is the CPU the scheduler
    /// has selected for its next run.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.NextProcessor`.
    ///
    /// [`Running`]: WindowsThreadState::Running
    /// [`Ready`]: WindowsThreadState::Ready
    /// [`Standby`]: WindowsThreadState::Standby
    pub fn next_processor(&self) -> Result<VcpuId, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let next_processor = self
            .vmi
            .read_u32(self.va + KTHREAD.NextProcessor.offset())?;

        // In newer Windows versions, the `NextProcessor` field is a union:
        //
        //     union {
        //       volatile ULONG NextProcessor;
        //
        //       struct {
        //         ULONG NextProcessorNumber : 31;
        //         ULONG SharedReadyQueue    : 1;
        //       };
        //     };

        // Mask out the `SharedReadyQueue` bit.
        let next_processor = next_processor & 0x7FFFFFFF;

        Ok(VcpuId(next_processor as u16))
    }

    /// Returns whether the thread is currently alertable.
    ///
    /// # Notes
    ///
    /// Usually only trustworthy when `_KTHREAD.State == Waiting`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Alertable`.
    pub fn alertable(&self) -> Result<bool, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let alertable = self.vmi.read_field(self.va, &KTHREAD.Alertable)?;

        Ok(KTHREAD.Alertable.extract(alertable) != 0)
    }

    /// Returns the thread's wait mode.
    ///
    /// # Notes
    ///
    /// Usually only trustworthy when `_KTHREAD.State == Waiting`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.WaitMode`.
    pub fn wait_mode(&self) -> Result<WindowsProcessorMode, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let value = self.vmi.read_u8(self.va + KTHREAD.WaitMode.offset())?;
        Ok(WindowsProcessorMode::from(value))
    }

    /// Returns the thread's wait reason.
    ///
    /// # Notes
    ///
    /// Usually only trustworthy when `_KTHREAD.State == Waiting`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.WaitReason`.
    pub fn wait_reason(&self) -> Result<WindowsThreadWaitReason, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let value = self.vmi.read_u8(self.va + KTHREAD.WaitReason.offset())?;
        Ok(WindowsThreadWaitReason::from(value))
    }

    /// Returns the thread's TEB.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Teb` for the native TEB, and
    /// `Teb64 + ROUND_TO_PAGES(sizeof(TEB))` for the WoW64 TEB.
    pub fn teb(&self) -> Result<Option<WindowsTeb<'a, Driver>>, VmiError> {
        let TEB = offset!(self.vmi, _TEB);

        let teb = match self.native_teb()? {
            Some(teb) => teb,
            None => return Ok(None),
        };

        let owning_process = self.process()?;
        if !owning_process.is_wow64()? {
            return Ok(Some(teb));
        }

        // #define WOW64_GET_TEB32_SAFE(teb64) \
        //         ((PTEB32) ((ULONGLONG)teb64 + WOW64_ROUND_TO_PAGES (sizeof (TEB))))

        let va = teb.va() + Driver::Architecture::va_align_up(Va(TEB.len() as u64));
        let root = owning_process.translation_root()?;

        Ok(Some(WindowsTeb::with_kind(
            self.vmi,
            va,
            root,
            WindowsWow64Kind::X86,
        )))
    }

    /// Returns the thread's native TEB.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Teb`.
    pub fn native_teb(&self) -> Result<Option<WindowsTeb<'a, Driver>>, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let va = self.vmi.read_va_native(self.va + KTHREAD.Teb.offset())?;

        if va.is_null() {
            return Ok(None);
        }

        let root = self.process()?.translation_root()?;

        Ok(Some(WindowsTeb::with_kind(
            self.vmi,
            va,
            root,
            WindowsWow64Kind::Native,
        )))
    }

    /// Returns the thread's trap frame.
    ///
    /// Points to the most recent user-to-kernel transition trap frame for the thread.
    /// It records the user-mode register state that was captured when the thread
    /// entered the kernel via a syscall, interrupt, or exception.
    ///
    /// Can be NULL when the thread is executing purely in kernel mode and has not
    /// entered via a user-mode trap.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.TrapFrame`.
    pub fn trap_frame(&self) -> Result<Option<WindowsTrapFrame<'a, Driver>>, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let va = self
            .vmi
            .read_va_native(self.va + KTHREAD.TrapFrame.offset())?;

        if va.is_null() {
            return Ok(None);
        }

        Ok(Some(WindowsTrapFrame::new(self.vmi, va)))
    }

    /// Returns the thread's scheduling state.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.State`.
    pub fn state(&self) -> Result<WindowsThreadState, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        let value = self.vmi.read_u8(self.va + KTHREAD.State.offset())?;
        Ok(WindowsThreadState::from(value))
    }

    /// Returns the saved kernel stack pointer for this thread.
    ///
    /// For threads that are not currently running, this is the stack pointer
    /// value saved during the last context switch (KiSwapContext).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.KernelStack`.
    pub fn kernel_stack(&self) -> Result<Va, VmiError> {
        let KTHREAD = offset!(self.vmi, _KTHREAD);

        self.vmi
            .read_va_native(self.va + KTHREAD.KernelStack.offset())
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for WindowsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the thread ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_ETHREAD.Cid.UniqueThread`.
    fn id(&self) -> Result<ThreadId, VmiError> {
        let ETHREAD = offset!(self.vmi, _ETHREAD);
        let CLIENT_ID = offset!(self.vmi, _CLIENT_ID);

        let result = self
            .vmi
            .read_u32(self.va + ETHREAD.Cid.offset() + CLIENT_ID.UniqueThread.offset())?;

        Ok(ThreadId(result))
    }

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError> {
        Ok(ThreadObject(self.va))
    }
}
