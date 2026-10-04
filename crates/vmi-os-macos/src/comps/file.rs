use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::MacOsVnode;
use crate::{ArchAdapter, MacOs, MacOsError, MacOsExt as _, offset};

/// The kind of object behind a file descriptor.
///
/// # Implementation Details
///
/// Corresponds to `file_type_t` (`DTYPE_*`) in `bsd/sys/file_internal.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsFileKind {
    /// A file or directory, `DTYPE_VNODE`.
    Vnode,

    /// A socket, `DTYPE_SOCKET`.
    Socket,

    /// POSIX shared memory, `DTYPE_PSXSHM`.
    PosixSharedMemory,

    /// A POSIX semaphore, `DTYPE_PSXSEM`.
    PosixSemaphore,

    /// A kqueue, `DTYPE_KQUEUE`.
    Kqueue,

    /// A pipe, `DTYPE_PIPE`.
    Pipe,

    /// An fsevents device, `DTYPE_FSEVENTS`.
    FsEvents,

    /// An AppleTalk socket, `DTYPE_ATALK`.
    AppleTalk,

    /// A network policy, `DTYPE_NETPOLICY`.
    NetworkPolicy,

    /// A Skywalk channel, `DTYPE_CHANNEL`.
    Channel,

    /// A Skywalk nexus, `DTYPE_NEXUS`.
    Nexus,

    /// A value that this crate does not know.
    Unknown(u32),
}

impl From<u32> for MacOsFileKind {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Vnode,
            2 => Self::Socket,
            3 => Self::PosixSharedMemory,
            4 => Self::PosixSemaphore,
            5 => Self::Kqueue,
            6 => Self::Pipe,
            7 => Self::FsEvents,
            8 => Self::AppleTalk,
            9 => Self::NetworkPolicy,
            10 => Self::Channel,
            11 => Self::Nexus,
            _ => Self::Unknown(value),
        }
    }
}

/// An open file of a macOS process.
///
/// # Implementation Details
///
/// Corresponds to `struct fileproc`, an entry in `filedesc.fd_ofiles`.
pub struct MacOsOpenFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, MacOs<Driver>>,

    /// File descriptor number.
    fd: i32,

    /// Address of the `struct fileproc`.
    va: Va,
}

impl<Driver> VmiVa for MacOsOpenFile<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> MacOsOpenFile<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new open file from its descriptor number and the address of
    /// its `struct fileproc`.
    pub fn new(vmi: VmiState<'a, MacOs<Driver>>, fd: i32, fileproc: Va) -> Self {
        Self {
            vmi,
            fd,
            va: fileproc,
        }
    }

    /// Returns the file descriptor number.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Returns the address of the `struct fileglob` shared by all
    /// descriptors of the open file.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `fileproc.fp_glob`.
    pub fn fileglob(&self) -> Result<Va, VmiError> {
        let fileproc = offset!(self.vmi, fileproc);

        let fileglob = self
            .vmi
            .os()
            .read_pointer(self.va + fileproc.fp_glob.offset())?;
        if fileglob.is_null() {
            return Err(MacOsError::CorruptedStruct("fileproc.fp_glob").into());
        }

        Ok(fileglob)
    }

    /// Returns the kind of object behind the descriptor.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `fileproc.fp_glob->fg_ops->fo_type`.
    pub fn kind(&self) -> Result<MacOsFileKind, VmiError> {
        let fileglob = offset!(self.vmi, fileglob);
        let fileops = offset!(self.vmi, fileops);

        let ops = self
            .vmi
            .os()
            .read_pointer(self.fileglob()? + fileglob.fg_ops.offset())?;

        if ops.is_null() {
            return Err(MacOsError::CorruptedStruct("fileglob.fg_ops").into());
        }

        Ok(MacOsFileKind::from(
            self.vmi.read_u32(ops + fileops.fo_type.offset())?,
        ))
    }

    /// Returns the address of the object behind the descriptor, such as a
    /// `struct vnode` or a `struct socket`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `fileproc.fp_glob->fg_data`.
    pub fn data(&self) -> Result<Va, VmiError> {
        let fileglob = offset!(self.vmi, fileglob);

        self.vmi
            .os()
            .read_pointer(self.fileglob()? + fileglob.fg_data.offset())
    }

    /// Returns the vnode behind the descriptor.
    ///
    /// Returns `None` when the descriptor does not refer to a vnode.
    pub fn vnode(&self) -> Result<Option<MacOsVnode<'a, Driver>>, VmiError> {
        if self.kind()? != MacOsFileKind::Vnode {
            return Ok(None);
        }

        let vnode = self.data()?;
        Ok((!vnode.is_null()).then(|| MacOsVnode::new(self.vmi, vnode)))
    }

    /// Returns the path of the vnode behind the descriptor.
    ///
    /// Returns `None` when the descriptor does not refer to a vnode or the
    /// path cannot be built. See [`MacOsVnode::path`] for how the path is
    /// built.
    pub fn path(&self) -> Result<Option<String>, VmiError> {
        match self.vnode()? {
            Some(vnode) => vnode.path(),
            None => Ok(None),
        }
    }
}
