use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead, os::ProcessObject};

use super::WindowsProcess;
use crate::{ArchAdapter, ListEntryIterator, WindowsOs, offset};

//
// The `_MM_SESSION_SPACE` structure got replaced in Windows 11 24H2
// with `_PSP_SESSION_SPACE`, however, its fields aren't included in
// the PDB symbols anymore.
//
// Fortunately, the layout of the beginning of the structure (up to
// and including the `ProcessList` field) appears to be unchanged so far,
// so, with heavy heart, we'll just hardcode the offsets.
//
// ```ignore
// typedef struct _MM_SESSION_SPACE {
//     /* 0x0000 */ volatile LONG ReferenceCount;
//     /* 0x0004 */ ULONG Flags;
//     /* 0x0008 */ ULONG SessionId;
//     /* 0x0010 */ LIST_ENTRY ProcessList;
//     ...
// } MM_SESSION_SPACE, *PMM_SESSION_SPACE;
// ```
//

struct Field {
    offset: u64,
}

impl Field {
    const fn offset(&self) -> u64 {
        self.offset
    }
}

#[expect(non_camel_case_types)]
struct _MM_SESSION_SPACE {
    SessionId: Field,
    ProcessList: Field,
}

const MM_SESSION_SPACE: _MM_SESSION_SPACE = _MM_SESSION_SPACE {
    SessionId: Field { offset: 0x0008 },
    ProcessList: Field { offset: 0x0010 },
};

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
        //let MM_SESSION_SPACE = offset!(self.vmi, _MM_SESSION_SPACE);

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
        //let MM_SESSION_SPACE = offset!(self.vmi, _MM_SESSION_SPACE);
        let EPROCESS = offset!(self.vmi, _EPROCESS);

        let vmi = self.vmi;
        Ok(ListEntryIterator::new(
            vmi,
            self.va + MM_SESSION_SPACE.ProcessList.offset(),
            EPROCESS.SessionProcessLinks.offset(),
        )
        .map(move |result| result.map(|entry| WindowsProcess::new(vmi, ProcessObject(entry)))))
    }
}
