use vmi_core::{
    Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{ProcessObject, ThreadId, ThreadObject, VmiOsThread},
};

use super::LinuxProcess;
use crate::{ArchAdapter, LinuxOs, offset};

/// The thread is a kernel thread (`PF_KTHREAD`).
pub(crate) const PF_KTHREAD: u32 = 0x0020_0000;

/// A Linux thread.
///
/// The kernel describes every thread with a `task_struct`. The threads of a
/// process form a thread group, which the group leader represents.
///
/// # Implementation Details
///
/// Corresponds to `task_struct`.
pub struct LinuxThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, LinuxOs<Driver>>,

    /// Address of the `task_struct` structure.
    va: Va,
}

impl<Driver> VmiVa for LinuxThread<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> LinuxThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Linux thread.
    pub fn new(vmi: VmiState<'a, LinuxOs<Driver>>, thread: ThreadObject) -> Self {
        Self { vmi, va: thread.0 }
    }

    /// Returns the process of the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.group_leader`.
    pub fn process(&self) -> Result<LinuxProcess<'a, Driver>, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        let group_leader = self
            .vmi
            .read_va_native(self.va + TASK_STRUCT.group_leader.offset())?;

        Ok(LinuxProcess::new(self.vmi, ProcessObject(group_leader)))
    }

    /// Returns the name of the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.comm`.
    pub fn name(&self) -> Result<String, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        self.vmi.read_string_limited(
            self.va + TASK_STRUCT.comm.offset(),
            TASK_STRUCT.comm.size() as usize,
        )
    }

    /// Returns the state of the thread (`TASK_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.__state`.
    pub fn state(&self) -> Result<u32, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        self.vmi.read_u32(self.va + TASK_STRUCT.__state.offset())
    }

    /// Returns the flags of the thread (`PF_*`).
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.flags`.
    pub fn flags(&self) -> Result<u32, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        self.vmi.read_u32(self.va + TASK_STRUCT.flags.offset())
    }

    /// Checks if the thread is a kernel thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `PF_KTHREAD` in `task_struct.flags`.
    pub fn is_kernel_thread(&self) -> Result<bool, VmiError> {
        Ok(self.flags()? & PF_KTHREAD != 0)
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for LinuxThread<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    type Os = LinuxOs<Driver>;

    /// Returns the thread ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `task_struct.pid`.
    fn id(&self) -> Result<ThreadId, VmiError> {
        let TASK_STRUCT = offset!(self.vmi, task_struct);

        let result = self.vmi.read_u32(self.va + TASK_STRUCT.pid.offset())?;

        Ok(ThreadId(result))
    }

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError> {
        Ok(ThreadObject(self.va))
    }
}
