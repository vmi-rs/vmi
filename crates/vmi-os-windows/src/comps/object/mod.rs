mod directory;
mod file;
mod process;
mod section;
mod thread;

use vmi_core::{
    os::{ProcessObject, ThreadObject},
    Architecture, Va, VmiDriver, VmiError, VmiState, VmiVa,
};

pub use self::{
    directory::WindowsDirectoryObject, file::WindowsFileObject, process::WindowsProcess,
    section::WindowsSectionObject, thread::WindowsThread,
};
use super::{
    macros::{impl_offsets, impl_symbols},
    WindowsObjectHeaderNameInfo,
};
use crate::{arch::ArchAdapter, WindowsOs, WindowsOsExt};

/// A Windows object.
///
/// A Windows object is a kernel-managed entity that can be referenced
/// by handles or pointers. It includes processes, threads, files, and other
/// system resources managed by the Windows Object Manager.
///
/// # Implementation Details
///
/// Corresponds to `_OBJECT_HEADER.Body`.
pub struct WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the object.
    va: Va,
}

impl<Driver> VmiVa for WindowsObject<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for WindowsObject<'_, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name_info = self.name_info();
        let typ = self.typ();

        f.debug_struct("WindowsObject")
            .field("typ", &typ)
            .field("name_info", &name_info)
            .finish()
    }
}

impl<'a, Driver> WindowsObject<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    impl_symbols!();
    impl_offsets!();

    /// Creates a new Windows object.
    pub fn new(vmi: VmiState<'a, Driver, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the virtual address of the `_OBJECT_HEADER` structure.
    ///
    /// # Implementation Details
    ///
    /// `_OBJECT_HEADER` is always at the beginning of the object.
    pub fn header(&self) -> Va {
        let offsets = self.offsets();
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        self.va - OBJECT_HEADER.Body.offset()
    }

    /// Returns the name information of the object.
    pub fn name_info(&self) -> Result<Option<WindowsObjectHeaderNameInfo<'a, Driver>>, VmiError> {
        let symbols = self.symbols();
        let offsets = self.offsets();
        let ObpInfoMaskToOffset = symbols.ObpInfoMaskToOffset;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let info_mask = self
            .vmi
            .read_u8(self.header() + OBJECT_HEADER.InfoMask.offset())?;

        bitflags::bitflags! {
            struct InfoFlags: u8 {
                const CREATOR_INFO = 0x01;
                const NAME_INFO = 0x02;
                const HANDLE_INFO = 0x04;
                const QUOTA_INFO = 0x08;
                const PROCESS_INFO = 0x10;
            }
        }

        let info_flags = InfoFlags::from_bits_truncate(info_mask);
        if !info_flags.contains(InfoFlags::NAME_INFO) {
            return Ok(None);
        }

        // Offset = ObpInfoMaskToOffset[OBJECT_HEADER->InfoMask & (DesiredHeaderBit | (DesiredHeaderBit-1))]

        let mask = info_mask & (InfoFlags::NAME_INFO.bits() | (InfoFlags::NAME_INFO.bits() - 1));
        let mask = mask as u64;

        let kernel_image_base = self.vmi.os().kernel_image_base()?;
        let offset = self
            .vmi
            .read_u8(kernel_image_base + ObpInfoMaskToOffset + mask)? as u64;

        Ok(Some(WindowsObjectHeaderNameInfo::new(
            self.vmi,
            self.header() - offset,
        )))
    }

    /// Returns the directory object associated with the object name.
    ///
    /// Shortcut for `self.name_info()?.directory()`.
    pub fn directory(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let name_info = match self.name_info()? {
            Some(name_info) => name_info,
            None => return Ok(None),
        };

        name_info.directory()
    }

    /// Returns the name of the object.
    ///
    /// Shortcut for `self.name_info()?.name()`.
    pub fn name(&self) -> Result<Option<String>, VmiError> {
        let name_info = match self.name_info()? {
            Some(name_info) => name_info,
            None => return Ok(None),
        };

        Ok(Some(name_info.name()?))
    }

    /// Constructs the full path of a named object from its name information.
    ///
    /// Shortcut for `self.name_info()?.full_path()`.
    pub fn full_path(&self) -> Result<Option<String>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::File(file)) => Ok(Some(file.full_path()?)),
            Some(WindowsObjectKind::Section(section)) => match section.file_object()? {
                Some(file) => Ok(Some(file.full_path()?)),
                None => Ok(None),
            },
            _ => {
                let name_info = match self.name_info()? {
                    Some(name_info) => name_info,
                    None => return Ok(None),
                };

                Ok(Some(name_info.full_path()?))
            }
        }
    }

    /// Returns the object type.
    pub fn typ(&self) -> Result<Option<WindowsObjectType>, VmiError> {
        self.vmi.os().object_type(self.va)
    }

    /// Returns the specific kind of this object.
    pub fn kind(&self) -> Result<Option<WindowsObjectKind<'a, Driver>>, VmiError> {
        let result = match self.typ()? {
            Some(WindowsObjectType::Directory) => {
                WindowsObjectKind::Directory(WindowsDirectoryObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectType::File) => {
                WindowsObjectKind::File(WindowsFileObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectType::Process) => {
                WindowsObjectKind::Process(WindowsProcess::new(self.vmi, ProcessObject(self.va)))
            }
            Some(WindowsObjectType::Section) => {
                WindowsObjectKind::Section(WindowsSectionObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectType::Thread) => {
                WindowsObjectKind::Thread(WindowsThread::new(self.vmi, ThreadObject(self.va)))
            }
            _ => return Ok(None),
        };

        Ok(Some(result))
    }

    /// Returns the object as a directory (`_OBJECT_DIRECTORY`).
    pub fn as_directory(&self) -> Result<Option<WindowsDirectoryObject<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Directory(directory)) => Ok(Some(directory)),
            _ => Ok(None),
        }
    }

    /// Returns the object as a file (`_FILE_OBJECT`).
    pub fn as_file(&self) -> Result<Option<WindowsFileObject<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::File(file)) => Ok(Some(file)),
            _ => Ok(None),
        }
    }

    /// Returns the object as a process (`_EPROCESS`).
    pub fn as_process(&self) -> Result<Option<WindowsProcess<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Process(process)) => Ok(Some(process)),
            _ => Ok(None),
        }
    }

    /// Returns the object as a section (`_SECTION_OBJECT`).
    pub fn as_section(&self) -> Result<Option<WindowsSectionObject<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Section(section)) => Ok(Some(section)),
            _ => Ok(None),
        }
    }

    /// Returns the object as a thread (`_ETHREAD`).
    pub fn as_thread(&self) -> Result<Option<WindowsThread<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Thread(thread)) => Ok(Some(thread)),
            _ => Ok(None),
        }
    }
}

/// Identifies the type of a Windows kernel object.
///
/// Windows uses a object-based kernel architecture where various system
/// resources (processes, threads, files, etc.) are represented as kernel
/// objects. This enum identifies the different types of objects that can
/// be encountered during introspection.
///
/// Each variant corresponds to a specific object type string used internally
/// by the Windows kernel. For example, "Process" for process objects,
/// "Thread" for thread objects, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsObjectType {
    /// ALPC Port object.
    ///
    /// Represented by `_ALPC_PORT` structure.
    /// Has `ALPC Port` type name.
    AlpcPort,

    /// Debug object.
    ///
    /// Represented by `_DEBUG_OBJECT` structure.
    /// Has `DebugObject` type name.
    DebugObject,

    /// Device object.
    ///
    /// Represented by `_DEVICE_OBJECT` structure.
    /// Has `Device` type name.
    Device,

    /// Directory object.
    ///
    /// Represented by `_OBJECT_DIRECTORY` structure.
    /// Has `Directory` type name.
    Directory,

    /// Driver object.
    ///
    /// Represented by `_DRIVER_OBJECT` structure.
    /// Has `Driver` type name.
    Driver,

    /// Event object.
    ///
    /// Represented by `_KEVENT` structure.
    /// Has `Event` type name.
    Event,

    /// File object.
    ///
    /// Represented by `_FILE_OBJECT` structure.
    /// Has `File` type name.
    File,

    /// Job object.
    ///
    /// Represented by `_EJOB` structure.
    /// Has `Job` type name.
    Job,

    /// Key object.
    ///
    /// Represented by `_CM_KEY_BODY` structure.
    /// Has `Key` type name.
    Key,

    /// Mutant object.
    ///
    /// Represented by `_KMUTANT` structure.
    /// Has `Mutant` type name.
    Mutant,

    /// Port object.
    ///
    /// Represented by `_PORT_MESSAGE` structure.
    /// Has `Port` type name.
    Port,

    /// Process object.
    ///
    /// Represented by `_EPROCESS` structure.
    /// Has `Process` type name.
    Process,

    /// Section object.
    ///
    /// Represented by `_SECTION` (or `_SECTION_OBJECT`) structure.
    /// Has `Section` type name.
    Section,

    /// Symbolic link object.
    ///
    /// Represented by `_OBJECT_SYMBOLIC_LINK` structure.
    /// Has `SymbolicLink` type name.
    SymbolicLink,

    /// Thread object.
    ///
    /// Represented by `_ETHREAD` structure.
    /// Has `Thread` type name.
    Thread,

    /// Timer object.
    ///
    /// Represented by `_KTIMER` structure.
    /// Has `Timer` type name.
    Timer,

    /// Token object.
    ///
    /// Represented by `_TOKEN` structure.
    /// Has `Token` type name.
    Token,

    /// Type object.
    ///
    /// Represented by `_OBJECT_TYPE` structure.
    /// Has `Type` type name.
    Type,
}

/// Represents a specific kind of Windows object.
pub enum WindowsObjectKind<'a, Driver>
where
    Driver: VmiDriver,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// A directory object (`_OBJECT_DIRECTORY`).
    Directory(WindowsDirectoryObject<'a, Driver>),

    /// A file object (`_FILE_OBJECT`).
    File(WindowsFileObject<'a, Driver>),

    /// A process object (`_EPROCESS`).
    Process(WindowsProcess<'a, Driver>),

    /// A section object (`_SECTION_OBJECT`).
    Section(WindowsSectionObject<'a, Driver>),

    /// A thread object (`_ETHREAD`).
    Thread(WindowsThread<'a, Driver>),
}
