use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::ProcessObject};

use super::{WindowsProcess, macros::impl_offsets};
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
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_MM_SESSION_SPACE` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsSession<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsSession<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    impl_offsets!();

    /// Creates a new Windows session space.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
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
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsProcess<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let offsets = self.offsets();
        let MM_SESSION_SPACE = &offsets._MM_SESSION_SPACE;
        let EPROCESS = &offsets._EPROCESS;

        let vmi = self.vmi;
        Ok(ListEntryIterator::new(
            vmi,
            self.va + MM_SESSION_SPACE.ProcessList.offset(),
            EPROCESS.SessionProcessLinks.offset(),
        )
        .map(move |result| result.map(|entry| WindowsProcess::new(vmi, ProcessObject(entry)))))
    }
}
