use vmi_core::{
    os::{ProcessObject, ThreadId, ThreadObject, VmiOsThread},
    Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa,
};

use super::super::macros::impl_offsets;
use crate::{ArchAdapter, WindowsObject, WindowsOs, WindowsProcess};

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
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_ETHREAD` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsThread<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsThread<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsThread<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsThread<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows thread.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, thread: ThreadObject) -> Self {
        Self { vmi, va: thread.0 }
    }

    /// Returns the process object associated with the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Process`.
    pub fn process(&self) -> Result<WindowsProcess<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KTHREAD = &offsets._KTHREAD;

        let process = self
            .vmi
            .read_va_native(self.va + KTHREAD.Process.offset())?;

        Ok(WindowsProcess::new(self.vmi, ProcessObject(process)))
    }

    /// Returns the process attached to the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.ApcState.Process`.
    pub fn attached_process(&self) -> Result<WindowsProcess<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KTHREAD = &offsets._KTHREAD;
        let KAPC_STATE = &offsets._KAPC_STATE;

        let process = self
            .vmi
            .read_va_native(self.va + KTHREAD.ApcState.offset() + KAPC_STATE.Process.offset())?;

        Ok(WindowsProcess::new(self.vmi, ProcessObject(process)))
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for WindowsThread<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    type Os = WindowsOs<Driver>;

    /// Returns the thread ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_ETHREAD.Cid.UniqueThread`.
    fn id(&self) -> Result<ThreadId, VmiError> {
        let offsets = self.offsets();
        let ETHREAD = &offsets._ETHREAD;
        let CLIENT_ID = &offsets._CLIENT_ID;

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
