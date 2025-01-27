use vmi_core::{
    os::{ProcessObject, ThreadId, ThreadObject, VmiOsThread},
    Architecture, Va, VmiDriver, VmiError, VmiState,
};

use crate::{arch::ArchAdapter, macros::impl_offsets, WindowsOs, WindowsOsProcess};

/// A Windows OS thread (`_ETHREAD`).
pub struct WindowsOsThread<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_ETHREAD` structure.
    va: Va,
}

/*
impl<Driver> Clone for WindowsOsThread<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn clone(&self) -> Self {
        Self {
            vmi: self.vmi.clone(),
            va: self.va,
        }
    }
}

impl<Driver> Copy for WindowsOsThread<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
}
*/

impl<Driver> From<WindowsOsThread<'_, Driver>> for Va
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsOsThread<Driver>) -> Self {
        value.va
    }
}

impl<'a, Driver> WindowsOsThread<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows OS process.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, thread: ThreadObject) -> Self {
        Self { vmi, va: thread.0 }
    }

    /// Returns the process object associated with the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.Process`.
    pub fn process(&self) -> Result<WindowsOsProcess<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KTHREAD = &offsets._KTHREAD;

        let process = self.vmi.read_va_native(self.va + KTHREAD.Process.offset)?;

        Ok(WindowsOsProcess::new(
            self.vmi.clone(),
            ProcessObject(process),
        ))
    }

    /// Returns the process attached to the thread.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_KTHREAD.ApcState.Process`.
    pub fn attached_process(&self) -> Result<WindowsOsProcess<'a, Driver>, VmiError> {
        let offsets = self.offsets();
        let KTHREAD = &offsets._KTHREAD;
        let KAPC_STATE = &offsets._KAPC_STATE;

        let process = self
            .vmi
            .read_va_native(self.va + KTHREAD.ApcState.offset + KAPC_STATE.Process.offset)?;

        Ok(WindowsOsProcess::new(
            self.vmi.clone(),
            ProcessObject(process),
        ))
    }
}

impl<'a, Driver> VmiOsThread<'a, Driver> for WindowsOsThread<'a, Driver>
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
            .read_u32(self.va + ETHREAD.Cid.offset + CLIENT_ID.UniqueThread.offset)?;

        Ok(ThreadId(result))
    }

    /// Returns the thread object.
    fn object(&self) -> Result<ThreadObject, VmiError> {
        Ok(ThreadObject(self.va))
    }
}
