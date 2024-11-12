use vmi_core::{os::ProcessObject, Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa};

use super::{macros::impl_offsets, WindowsObject, WindowsProcess};
use crate::{ArchAdapter, ListEntryIterator, WindowsOs};

/// A Windows session space.
///
/// The session space is a kernel structure that contains the
/// session-specific data for a process.
///
/// Each logon session (e.g., when a user connects via Remote Desktop) gets
/// a separate instance of `_MM_SESSION_SPACE`.
///
/// # Implementation Details
///
/// Corresponds to `_MM_SESSION_SPACE`.
pub struct WindowsSession<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the `_MM_SESSION_SPACE` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsSession<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from(value: WindowsSession<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<Driver> VmiVa for WindowsSession<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSession<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows session space.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the session ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MM_SESSION_SPACE.SessionId`.
    pub fn id(&self) -> Result<u32, VmiError> {
        let offsets = self.offsets();
        let MM_SESSION_SPACE = &offsets._MM_SESSION_SPACE;

        self.vmi
            .read_u32(self.va + MM_SESSION_SPACE.SessionId.offset())
    }

    /// Returns the list of processes in the session.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_MM_SESSION_SPACE.ProcessList`.
    pub fn processes(
        &'a self,
    ) -> Result<impl Iterator<Item = Result<WindowsProcess<'a, Driver>, VmiError>>, VmiError> {
        let offsets = self.offsets();
        let MM_SESSION_SPACE = &offsets._MM_SESSION_SPACE;
        let EPROCESS = &offsets._EPROCESS;

        Ok(ListEntryIterator::new(
            self.vmi,
            self.va + MM_SESSION_SPACE.ProcessList.offset(),
            EPROCESS.SessionProcessLinks.offset(),
        )
        .map(move |result| result.map(|entry| WindowsProcess::new(self.vmi, ProcessObject(entry)))))
    }
}
