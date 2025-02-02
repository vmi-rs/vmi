use serde::{Deserialize, Serialize};

use super::VmiOs;
use crate::{MemoryAccess, Pa, Va, VmiDriver, VmiError};

/// A process object within a system.
///
/// Equivalent to `EPROCESS*` on Windows or `task_struct*` on Linux.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ProcessObject(pub Va);

impl ProcessObject {
    /// Checks if the process object is a null reference.
    pub fn is_null(&self) -> bool {
        self.0 .0 == 0
    }

    /// Converts the process object to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.0 .0
    }
}

impl From<Va> for ProcessObject {
    fn from(va: Va) -> Self {
        Self(va)
    }
}

impl From<ProcessObject> for Va {
    fn from(value: ProcessObject) -> Self {
        value.0
    }
}

impl std::fmt::Display for ProcessObject {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A thread object within a system.
///
/// Equivalent to `ETHREAD*` on Windows.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ThreadObject(pub Va);

impl ThreadObject {
    /// Checks if the thread object is a null reference.
    pub fn is_null(&self) -> bool {
        self.0 .0 == 0
    }

    /// Converts the thread object to a 64-bit unsigned integer.
    pub fn to_u64(&self) -> u64 {
        self.0 .0
    }
}

impl From<Va> for ThreadObject {
    fn from(va: Va) -> Self {
        Self(va)
    }
}

impl From<ThreadObject> for Va {
    fn from(value: ThreadObject) -> Self {
        value.0
    }
}

impl std::fmt::Display for ThreadObject {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A process ID within a system.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ProcessId(pub u32);

impl From<u32> for ProcessId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ProcessId> for u32 {
    fn from(value: ProcessId) -> Self {
        value.0
    }
}

impl std::fmt::Display for ProcessId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A thread ID within a system.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ThreadId(pub u32);

impl From<u32> for ThreadId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ThreadId> for u32 {
    fn from(value: ThreadId) -> Self {
        value.0
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The architecture of the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsArchitecture {
    /// The architecture is unknown.
    Unknown,

    /// The x86 architecture.
    X86,

    /// The x86-64 architecture.
    Amd64,
}

/// Represents information about a kernel module in the target system.
#[derive(Debug, Serialize, Deserialize)]
pub struct OsModule {
    /// The base address of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.DllBase`
    /// - **Linux**:
    ///   - since v6.4-rc1: `module::mem[0 /* MOD_TEXT */].base`
    ///   - before v6.4-rc1: `module::core_layout.base`
    pub base_address: Va,

    /// The size of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.SizeOfImage`
    /// - **Linux**:
    ///   - since v6.4-rc1: sum of `module::mem[MOD_*].size`
    ///   - before v6.4-rc1: `module::init_layout.size + module::core_layout.size (+ module::data_layout.size)`
    pub size: u64,

    /// The short name of the module.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `KLDR_DATA_TABLE_ENTRY.BaseDllName`
    /// - **Linux**: `module::name`
    pub name: String,
}

/// Represents information about a process in the target system.
#[derive(Debug, Serialize, Deserialize)]
pub struct OsProcess {
    /// The PID of the process.
    pub id: ProcessId,

    /// The process object.
    pub object: ProcessObject,

    /// The short name of the process.
    ///
    /// # Platform-specific
    ///
    /// - **Windows**: `_EPROCESS::ImageFileName` (limited to 16 characters).
    /// - **Linux**: `_task_struct::comm` (limited to 16 characters).
    pub name: String,

    /// The translation root of the process.
    pub translation_root: Pa,
}

/// A region of memory within a process.
#[derive(Debug, Serialize, Deserialize)]
pub struct OsRegion {
    /// The start address of the region.
    pub start: Va,

    /// The end address of the region.
    pub end: Va,

    /// The protection flags of the region.
    pub protection: MemoryAccess,

    /// The kind of memory region.
    pub kind: OsRegionKind,
}

/// Specifies the kind of memory region.
#[derive(Debug, Serialize, Deserialize)]
pub enum OsRegionKind {
    /// A private region of memory.
    ///
    /// Such regions are usually created by functions like `VirtualAlloc` on
    /// Windows.
    Private,

    /// A mapped region of memory. Might be backed by a file.
    ///
    /// Such regions are usually created by functions like `MapViewOfFile` on
    /// Windows.
    Mapped(OsMapped),
}

/// Specifies the kind of memory region.
pub enum VmiOsRegionKind<'a, Driver, Os>
where
    Driver: VmiDriver,
    Os: VmiOs<Driver>,
    Self: 'a,
{
    /// A private region of memory.
    ///
    /// Such regions are usually created by functions like `VirtualAlloc` on
    /// Windows.
    Private,

    /// A mapped region of memory. Might be backed by a file.
    ///
    /// Such regions are usually created by functions like `MapViewOfFile` on
    /// Windows.
    Mapped(Os::Mapped<'a>),
}

/// Contains information about a mapped memory region.
#[derive(Debug, Serialize, Deserialize)]
pub struct OsMapped {
    /// The path to the file backing the region.
    ///
    /// This field is represented as a [`Result<Option<String>, VmiError>`] to
    /// handle cases where the path is not available (e.g., due to a page
    /// fault).
    #[serde(with = "serde_result_option")]
    pub path: Result<Option<String>, VmiError>,
}

/// An exported symbol from an image (e.g., DLL or .so file).
#[derive(Debug, Serialize, Deserialize)]
pub struct OsImageExportedSymbol {
    /// The name of the symbol.
    pub name: String,

    /// The virtual address of the symbol.
    pub address: Va,
}

/// Custom serialization module for [`Result<Option<String>, VmiError>`].
///
/// Provides custom serialization and deserialization logic for handling
/// the path field in [`OsMapped`], which may be unavailable due to paging
/// issues.
mod serde_result_option {
    use crate::VmiError;

    pub fn serialize<S>(
        value: &Result<Option<String>, VmiError>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value {
            Ok(Some(value)) => serializer.serialize_some(value),
            _ => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Result<Option<String>, VmiError>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize as _;

        let value = Option::deserialize(deserializer)?;
        match value {
            Some(value) => Ok(Ok(Some(value))),
            None => Ok(Err(VmiError::Other("PageFault"))),
        }
    }
}
