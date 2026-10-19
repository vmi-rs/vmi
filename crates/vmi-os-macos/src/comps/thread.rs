use vmi_core::{
    Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{ProcessObject, ThreadId, ThreadObject, VmiOsThread},
};

use super::{MacOsProcess, MacOsSavedState};
use crate::{ArchAdapter, MacOs, MacOsError, MacOsExt as _, offset};

/// A macOS thread.
///
/// # Implementation Details
///
/// Corresponds to `struct thread`.
pub struct MacOsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// Address of the `struct thread`.
    va: Va,
}

impl<Driver> VmiVa for MacOsThread<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new macOS thread.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, thread: ThreadObject) -> Self {
        Self { vmi, va: thread.0 }
    }

    /// Returns the 64-bit thread ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.thread_id`.
    pub fn thread_id(&self) -> Result<u64, VmiError> {
        let thread = offset!(self.vmi, thread);

        self.vmi.read_u64(self.va + thread.thread_id.offset())
    }

    /// Returns the address of the read-only thread data.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.t_tro`.
    fn thread_ro(&self) -> Result<Va, VmiError> {
        let thread = offset!(self.vmi, thread);

        let thread_ro = self
            .vmi
            .os()
            .read_pointer(self.va + thread.t_tro.offset())?;
        if thread_ro.is_null() {
            return Err(MacOsError::CorruptedStruct("thread.t_tro").into());
        }

        Ok(thread_ro)
    }

    /// Returns the address of the task that owns the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.t_tro->tro_task`.
    pub fn task(&self) -> Result<Va, VmiError> {
        let thread_ro = offset!(self.vmi, thread_ro);

        self.vmi
            .os()
            .read_pointer(self.thread_ro()? + thread_ro.tro_task.offset())
    }

    /// Returns the process that owns the thread.
    ///
    /// Fails with [`MacOsError::CorruptedStruct`] when the thread has no
    /// process, see [`attached_process`](Self::attached_process).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.t_tro->tro_proc`.
    pub fn process(&self) -> Result<MacOsProcess<'a, Driver>, VmiError> {
        match self.attached_process()? {
            Some(process) => Ok(process),
            None => Err(MacOsError::CorruptedStruct("thread_ro.tro_proc").into()),
        }
    }

    /// Returns the process that owns the thread, or `None` once the process
    /// has been detached from it.
    ///
    /// The exiting thread keeps running kernel cleanup after `proc_exit`
    /// detaches its process (xnu `bsd/kern/kern_exit.c`, `proc_set_task`,
    /// `set_bsdtask_info` and `clear_thread_ro_proc`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.t_tro->tro_proc`, which is `NULL` once cleared.
    pub fn attached_process(&self) -> Result<Option<MacOsProcess<'a, Driver>>, VmiError> {
        let thread_ro = offset!(self.vmi, thread_ro);

        let process = self
            .vmi
            .os()
            .read_pointer(self.thread_ro()? + thread_ro.tro_proc.offset())?;

        if process.is_null() {
            return Ok(None);
        }

        Ok(Some(MacOsProcess::new(self.vmi, ProcessObject(process))))
    }

    /// Returns the user-mode register state of the thread.
    ///
    /// Returns `None` when the thread has no user-mode register state.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `thread.machine.upcb`.
    pub fn user_saved_state(&self) -> Result<Option<MacOsSavedState<'a, Driver>>, VmiError> {
        let thread = offset!(self.vmi, thread);
        let machine_thread = offset!(self.vmi, machine_thread);

        let saved_state = self
            .vmi
            .os()
            .read_pointer(self.va + thread.machine.offset() + machine_thread.upcb.offset())?;

        if saved_state.is_null() {
            return Ok(None);
        }

        Ok(Some(MacOsSavedState::new(self.vmi, saved_state)))
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for MacOsThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = MacOs<Driver>;

    /// Returns the thread ID.
    ///
    /// Fails when the 64-bit [`thread_id`](Self::thread_id) does not fit into
    /// 32 bits.
    fn id(&self) -> Result<ThreadId, VmiError> {
        let thread_id = self.thread_id()?;

        match u32::try_from(thread_id) {
            Ok(id) => Ok(ThreadId(id)),
            Err(_) => Err(MacOsError::ThreadIdOutOfRange(thread_id).into()),
        }
    }

    fn object(&self) -> Result<ThreadObject, VmiError> {
        Ok(ThreadObject(self.va))
    }
}
