mod directory;
mod file;
mod key;
mod object_type;
mod process;
mod section;
mod thread;

use vmi_core::{
    Architecture, Va, VmiError, VmiState, VmiVa,
    driver::VmiRead,
    os::{ProcessObject, ThreadObject},
};

pub use self::{
    directory::WindowsDirectoryObject,
    file::WindowsFileObject,
    key::WindowsKey,
    object_type::WindowsObjectType,
    process::WindowsProcess,
    section::WindowsSectionObject,
    thread::{WindowsThread, WindowsThreadState},
};
use super::{
    WindowsObjectHeaderNameInfo,
    macros::{impl_offsets, impl_symbols},
};
use crate::{WindowsOs, WindowsOsExt, arch::ArchAdapter};

/// Trait for types that can be converted from a [`WindowsObject`].
pub trait FromWindowsObject<'a, Driver>: Sized
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// Attempts to convert a [`WindowsObject`] into a specific object type.
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError>;
}

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
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, Driver, WindowsOs<Driver>>,

    /// The virtual address of the object.
    va: Va,
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        // Any object can be converted to itself.
        Ok(Some(object))
    }
}

impl<Driver> VmiVa for WindowsObject<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<Driver> std::fmt::Debug for WindowsObject<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name_info = self.name_info();
        let typ = self.type_kind();

        f.debug_struct("WindowsObject")
            .field("typ", &typ)
            .field("name_info", &name_info)
            .finish()
    }
}

impl<'a, Driver> WindowsObject<'a, Driver>
where
    Driver: VmiRead,
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
    /// Shortcut for [`self.name_info()?.directory()`].
    ///
    /// [`self.name_info()?.directory()`]: WindowsObjectHeaderNameInfo::directory
    pub fn directory(&self) -> Result<Option<WindowsObject<'a, Driver>>, VmiError> {
        let name_info = match self.name_info()? {
            Some(name_info) => name_info,
            None => return Ok(None),
        };

        name_info.directory()
    }

    /// Returns the name of the object.
    ///
    /// Shortcut for [`self.name_info()?.name()`].
    ///
    /// [`self.name_info()?.name()`]: WindowsObjectHeaderNameInfo::name
    pub fn name(&self) -> Result<Option<String>, VmiError> {
        let name_info = match self.name_info()? {
            Some(name_info) => name_info,
            None => return Ok(None),
        };

        Ok(Some(name_info.name()?))
    }

    /// Constructs the full path of a named object from its name information.
    ///
    /// Shortcut for [`self.name_info()?.full_path()`].
    ///
    /// [`self.name_info()?.full_path()`]: WindowsObjectHeaderNameInfo::full_path
    pub fn full_path(&self) -> Result<Option<String>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::File(file)) => Ok(Some(file.full_path()?)),
            Some(WindowsObjectKind::Key(key)) => Ok(Some(key.full_path()?)),
            Some(WindowsObjectKind::Section(section)) => section.full_path(),
            _ => {
                let name_info = match self.name_info()? {
                    Some(name_info) => name_info,
                    None => return Ok(None),
                };

                Ok(Some(name_info.full_path()?))
            }
        }
    }

    /// Returns the type of a Windows kernel object.
    ///
    /// This method analyzes the object header of a kernel object and returns
    /// its type object (`_OBJECT_TYPE`). It handles the obfuscation introduced
    /// by the object header cookie, ensuring accurate type identification even
    /// on systems with this security feature enabled.
    pub fn object_type(&self) -> Result<WindowsObjectType<'a, Driver>, VmiError> {
        let symbols = self.symbols();
        let offsets = self.offsets();
        let ObTypeIndexTable = symbols.ObTypeIndexTable;
        let OBJECT_HEADER = &offsets._OBJECT_HEADER;

        let object_header = self.va - OBJECT_HEADER.Body.offset();
        let type_index = self
            .vmi
            .read_u8(object_header + OBJECT_HEADER.TypeIndex.offset())?;

        let index = match self.vmi.os().object_header_cookie()? {
            Some(cookie) => {
                //
                // TypeIndex
                //     ^ 2nd least significate byte of OBJECT_HEADER address
                //     ^ nt!ObHeaderCookie
                // ref: https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a
                //

                let salt = (object_header.0 >> 8) as u8;
                type_index ^ salt ^ cookie
            }
            None => type_index,
        };

        let index = index as u64;

        let kernel_image_base = self.vmi.os().kernel_image_base()?;
        let object_type = self.vmi.read_va_native(
            kernel_image_base + ObTypeIndexTable + index * 8, // REVIEW: replace 8 with registers.address_width()?
        )?;

        Ok(WindowsObjectType::new(self.vmi, object_type))
    }

    /// Returns the object type name.
    ///
    /// Shortcut for [`self.object_type()?.name()`].
    ///
    /// [`self.object_type()?.name()`]: WindowsObjectType::name
    pub fn type_name(&self) -> Result<String, VmiError> {
        self.object_type()?.name()
    }

    /// Returns the object type kind.
    ///
    /// Shortcut for [`self.object_type()?.kind()`].
    ///
    /// [`self.object_type()?.kind()`]: WindowsObjectType::kind
    pub fn type_kind(&self) -> Result<Option<WindowsObjectTypeKind>, VmiError> {
        self.object_type()?.kind()
    }

    /// Returns the specific kind of this object.
    pub fn kind(&self) -> Result<Option<WindowsObjectKind<'a, Driver>>, VmiError> {
        let result = match self.type_kind()? {
            Some(WindowsObjectTypeKind::Directory) => {
                WindowsObjectKind::Directory(WindowsDirectoryObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectTypeKind::File) => {
                WindowsObjectKind::File(WindowsFileObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectTypeKind::Key) => {
                WindowsObjectKind::Key(WindowsKey::new(self.vmi, self.va))
            }
            Some(WindowsObjectTypeKind::Process) => {
                WindowsObjectKind::Process(WindowsProcess::new(self.vmi, ProcessObject(self.va)))
            }
            Some(WindowsObjectTypeKind::Section) => {
                WindowsObjectKind::Section(WindowsSectionObject::new(self.vmi, self.va))
            }
            Some(WindowsObjectTypeKind::Thread) => {
                WindowsObjectKind::Thread(WindowsThread::new(self.vmi, ThreadObject(self.va)))
            }
            Some(WindowsObjectTypeKind::Type) => {
                WindowsObjectKind::Type(WindowsObjectType::new(self.vmi, self.va))
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

    /// Returns the object as a key (`_CM_KEY_BODY`).
    pub fn as_key(&self) -> Result<Option<WindowsKey<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Key(key)) => Ok(Some(key)),
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

    /// Returns the object as an object type (`_OBJECT_TYPE`).
    pub fn as_type(&self) -> Result<Option<WindowsObjectType<'a, Driver>>, VmiError> {
        match self.kind()? {
            Some(WindowsObjectKind::Type(object_type)) => Ok(Some(object_type)),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsObjectTypeKind {
    /// Activation object.
    ///
    /// Has `ActivationObject` type name.
    ActivationObject,

    /// Activity reference object.
    ///
    /// Has `ActivityReference` type name.
    ActivityReference,

    /// Adapter object.
    ///
    /// Represented by `_ADAPTER_OBJECT` structure.
    /// Has `Adapter` type name.
    Adapter,

    /// ALPC Port object.
    ///
    /// Represented by `_ALPC_PORT` structure.
    /// Has `ALPC Port` type name.
    AlpcPort,

    /// Callback object.
    ///
    /// Has `Callback` type name.
    Callback,

    /// Composition object.
    ///
    /// Has `Composition` type name.
    Composition,

    /// Controller object.
    ///
    /// Has `Controller` type name.
    Controller,

    /// Core messaging object.
    ///
    /// Has `CoreMessaging` type name.
    CoreMessaging,

    /// Coverage sampler object.
    ///
    /// Has `CoverageSampler` type name.
    CoverageSampler,

    /// CPU partition object.
    ///
    /// Has `CpuPartition` type name.
    CpuPartition,

    /// Debug object.
    ///
    /// Represented by `_DEBUG_OBJECT` structure.
    /// Has `DebugObject` type name.
    DebugObject,

    /// Desktop object.
    ///
    /// Has `Desktop` type name.
    Desktop,

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

    /// DMA adapter object.
    ///
    /// Has `DmaAdapter` type name.
    DmaAdapter,

    /// Driver object.
    ///
    /// Represented by `_DRIVER_OBJECT` structure.
    /// Has `Driver` type name.
    Driver,

    /// DX Composition object.
    ///
    /// Has `DxgkCompositionObject` type name.
    DxgkCompositionObject,

    /// DX Display Manager object.
    ///
    /// Has `DxgkDisplayManagerObject` type name.
    DxgkDisplayManagerObject,

    /// DX Shared Bundle object.
    ///
    /// Has `DxgkSharedBundleObject` type name.
    DxgkSharedBundleObject,

    /// DX Shared Keyed Mutex object.
    ///
    /// Has `DxgkSharedKeyedMutexObject` type name.
    DxgkSharedKeyedMutexObject,

    /// DX Shared Protected Session object.
    ///
    /// Has `DxgkSharedProtectedSessionObject` type name.
    DxgkSharedProtectedSessionObject,

    /// DX Shared Resource object.
    ///
    /// Has `DxgkSharedResource` type name.
    DxgkSharedResource,

    /// DX Shared Swap Chain object.
    ///
    /// Has `DxgkSharedSwapChainObject` type name.
    DxgkSharedSwapChainObject,

    /// DX Shared Sync object.
    ///
    /// Has `DxgkSharedSyncObject` type name.
    DxgkSharedSyncObject,

    /// Energy tracker object.
    ///
    /// Has `EnergyTracker` type name.
    EnergyTracker,

    /// ETW consumer object.
    ///
    /// Has `EtwConsumer` type name.
    EtwConsumer,

    /// ETW registration object.
    ///
    /// Has `EtwRegistration` type name.
    EtwRegistration,

    /// ETW session demux entry object.
    ///
    /// Has `EtwSessionDemuxEntry` type name.
    EtwSessionDemuxEntry,

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

    /// Filter communication port object.
    ///
    /// Has `FilterCommunicationPort` type name.
    FilterCommunicationPort,

    /// Filter connection port object.
    ///
    /// Has `FilterConnectionPort` type name.
    FilterConnectionPort,

    /// I/O completion object.
    ///
    /// Has `IoCompletion` type name.
    IoCompletion,

    /// I/O completion reserve object.
    ///
    /// Has `IoCompletionReserve` type name.
    IoCompletionReserve,

    /// I/O ring object.
    ///
    /// Has `IoRing` type name.
    IoRing,

    /// IR timer object.
    ///
    /// Has `IRTimer` type name.
    IRTimer,

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

    /// Keyed event object.
    ///
    /// Has `KeyedEvent` type name.
    KeyedEvent,

    /// Mutant object.
    ///
    /// Represented by `_KMUTANT` structure.
    /// Has `Mutant` type name.
    Mutant,

    /// NDIS CM state object.
    ///
    /// Has `NdisCmState` type name.
    NdisCmState,

    /// Partition object.
    ///
    /// Has `Partition` type name.
    Partition,

    /// Performance counter object.
    ///
    /// Has `PcwObject` type name.
    PcwObject,

    /// Power request object.
    ///
    /// Has `PowerRequest` type name.
    PowerRequest,

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

    /// Process state change object.
    ///
    /// Has `ProcessStateChange` type name.
    ProcessStateChange,

    /// Profile object.
    ///
    /// Has `Profile` type name.
    Profile,

    /// Sile context (non-paged) object.
    ///
    /// Has `PsSiloContextNonPaged` type name.
    PsSiloContextNonPaged,

    /// Sile context (paged) object.
    ///
    /// Has `PsSiloContextPaged` type name.
    PsSiloContextPaged,

    /// Raw input manager object.
    ///
    /// Has `RawInputManager` type name.
    RawInputManager,

    /// Registry transaction object.
    ///
    /// Has `RegistryTransaction` type name.
    RegistryTransaction,

    /// Section object.
    ///
    /// Represented by `_SECTION` (or `_SECTION_OBJECT`) structure.
    /// Has `Section` type name.
    Section,

    /// Semaphore object.
    ///
    /// Represented by `_KSEMAPHORE` structure.
    /// Has `Semaphore` type name.
    Semaphore,

    /// Session object.
    ///
    /// Has `Session` type name.
    Session,

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

    /// Thread state change object.
    ///
    /// Has `ThreadStateChange` type name.
    ThreadStateChange,

    /// Timer object.
    ///
    /// Represented by `_KTIMER` structure.
    /// Has `Timer` type name.
    Timer,

    /// Transaction manager (Enlistment) object.
    ///
    /// Has `TmEn` type name.
    TmEn,

    /// Transaction manager (Resource Manager) object.
    ///
    /// Has `TmRm` type name.
    TmRm,

    /// Transaction manager object.
    TmTm,

    /// Transaction object.
    TmTx,

    /// Token object.
    ///
    /// Represented by `_TOKEN` structure.
    /// Has `Token` type name.
    Token,

    /// Thread pool worker factory object.
    ///
    /// Has `TpWorkerFactory` type name.
    TpWorkerFactory,

    /// Type object.
    ///
    /// Represented by `_OBJECT_TYPE` structure.
    /// Has `Type` type name.
    Type,

    /// User APC reserve object.
    ///
    /// Has `UserApcReserve` type name.
    UserApcReserve,

    /// Wait completion packet object.
    ///
    /// Has `WaitCompletionPacket` type name.
    WaitCompletionPacket,

    /// Window station object.
    ///
    /// Has `WindowStation` type name.
    WindowStation,

    /// WMI GUID object.
    ///
    /// Has `WmiGuid` type name.
    WmiGuid,
}

/// Error parsing a Windows object type.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseObjectTypeError;

impl std::str::FromStr for WindowsObjectTypeKind {
    type Err = ParseObjectTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use WindowsObjectTypeKind::*;

        match s {
            "ActivationObject" => Ok(ActivationObject),
            "ActivityReference" => Ok(ActivityReference),
            "Adapter" => Ok(Adapter),
            "ALPC Port" => Ok(AlpcPort),
            "Callback" => Ok(Callback),
            "Composition" => Ok(Composition),
            "Controller" => Ok(Controller),
            "CoreMessaging" => Ok(CoreMessaging),
            "CoverageSampler" => Ok(CoverageSampler),
            "CpuPartition" => Ok(CpuPartition),
            "DebugObject" => Ok(DebugObject),
            "Desktop" => Ok(Desktop),
            "Device" => Ok(Device),
            "Directory" => Ok(Directory),
            "DmaAdapter" => Ok(DmaAdapter),
            "Driver" => Ok(Driver),
            "DxgkCompositionObject" => Ok(DxgkCompositionObject),
            "DxgkDisplayManagerObject" => Ok(DxgkDisplayManagerObject),
            "DxgkSharedBundleObject" => Ok(DxgkSharedBundleObject),
            "DxgkSharedKeyedMutexObject" => Ok(DxgkSharedKeyedMutexObject),
            "DxgkSharedProtectedSessionObject" => Ok(DxgkSharedProtectedSessionObject),
            "DxgkSharedResource" => Ok(DxgkSharedResource),
            "DxgkSharedSwapChainObject" => Ok(DxgkSharedSwapChainObject),
            "DxgkSharedSyncObject" => Ok(DxgkSharedSyncObject),
            "EnergyTracker" => Ok(EnergyTracker),
            "EtwConsumer" => Ok(EtwConsumer),
            "EtwRegistration" => Ok(EtwRegistration),
            "EtwSessionDemuxEntry" => Ok(EtwSessionDemuxEntry),
            "Event" => Ok(Event),
            "File" => Ok(File),
            "FilterCommunicationPort" => Ok(FilterCommunicationPort),
            "FilterConnectionPort" => Ok(FilterConnectionPort),
            "IoCompletion" => Ok(IoCompletion),
            "IoCompletionReserve" => Ok(IoCompletionReserve),
            "IoRing" => Ok(IoRing),
            "IRTimer" => Ok(IRTimer),
            "Job" => Ok(Job),
            "Key" => Ok(Key),
            "KeyedEvent" => Ok(KeyedEvent),
            "Mutant" => Ok(Mutant),
            "NdisCmState" => Ok(NdisCmState),
            "Partition" => Ok(Partition),
            "PcwObject" => Ok(PcwObject),
            "PowerRequest" => Ok(PowerRequest),
            "Port" => Ok(Port),
            "Process" => Ok(Process),
            "ProcessStateChange" => Ok(ProcessStateChange),
            "Profile" => Ok(Profile),
            "PsSiloContextNonPaged" => Ok(PsSiloContextNonPaged),
            "PsSiloContextPaged" => Ok(PsSiloContextPaged),
            "RawInputManager" => Ok(RawInputManager),
            "RegistryTransaction" => Ok(RegistryTransaction),
            "Section" => Ok(Section),
            "Semaphore" => Ok(Semaphore),
            "Session" => Ok(Session),
            "SymbolicLink" => Ok(SymbolicLink),
            "Thread" => Ok(Thread),
            "ThreadStateChange" => Ok(ThreadStateChange),
            "Timer" => Ok(Timer),
            "TmEn" => Ok(TmEn),
            "TmRm" => Ok(TmRm),
            "TmTm" => Ok(TmTm),
            "TmTx" => Ok(TmTx),
            "Token" => Ok(Token),
            "TpWorkerFactory" => Ok(TpWorkerFactory),
            "Type" => Ok(Type),
            "UserApcReserve" => Ok(UserApcReserve),
            "WaitCompletionPacket" => Ok(WaitCompletionPacket),
            "WindowStation" => Ok(WindowStation),
            "WmiGuid" => Ok(WmiGuid),
            _ => Err(ParseObjectTypeError),
        }
    }
}

/// Represents a specific kind of Windows object.
pub enum WindowsObjectKind<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: Architecture + ArchAdapter<Driver>,
{
    /// A directory object (`_OBJECT_DIRECTORY`).
    Directory(WindowsDirectoryObject<'a, Driver>),

    /// A file object (`_FILE_OBJECT`).
    File(WindowsFileObject<'a, Driver>),

    /// A registry key object (`_CM_KEY_BODY`).
    Key(WindowsKey<'a, Driver>),

    /// A process object (`_EPROCESS`).
    Process(WindowsProcess<'a, Driver>),

    /// A section object (`_SECTION_OBJECT`).
    Section(WindowsSectionObject<'a, Driver>),

    /// A thread object (`_ETHREAD`).
    Thread(WindowsThread<'a, Driver>),

    /// An object type object (`_OBJECT_TYPE`).
    Type(WindowsObjectType<'a, Driver>),
}
