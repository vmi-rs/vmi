use vmi_core::os::ProcessId;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Protects the object from being closed by certain APIs (platform specific).
pub const OBJ_PROTECT_CLOSE: u32 = 0x00000001;

/// This handle can be inherited by child processes of the current process.
pub const OBJ_INHERIT: u32 = 0x00000002;

/// Request auditing when the object is closed.
pub const OBJ_AUDIT_OBJECT_CLOSE: u32 = 0x00000004;

/// Prevents automatic rights upgrade on the object.
pub const OBJ_NO_RIGHTS_UPGRADE: u32 = 0x00000008;

/// This flag only applies to objects that are named within the object manager.
/// By default such objects are deleted when all open handles to them are closed.
/// If this flag is specified, the object is not deleted when all open handles are closed.
/// The NtMakeTemporaryObject function can be used to delete permanent objects.
pub const OBJ_PERMANENT: u32 = 0x00000010;

/// Only a single handle can be open for this object.
pub const OBJ_EXCLUSIVE: u32 = 0x00000020;

/// If this flag is specified, a case-insensitive comparison is used when matching the name
/// pointed to by the ObjectName member against the names of existing objects.
/// Otherwise, object names are compared using the default system settings.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

/// If this flag is specified, by using the object handle, to a routine that creates objects
/// and if that object already exists, the routine should open that object.
/// Otherwise, the routine creating the object returns an NTSTATUS code of STATUS_OBJECT_NAME_COLLISION.
pub const OBJ_OPENIF: u32 = 0x00000080;

/// If an object handle, with this flag set, is passed to a routine that opens objects
/// and if the object is a symbolic link object, the routine should open the symbolic link
/// object itself, rather than the object that the symbolic link refers to (which is the default behavior).
pub const OBJ_OPENLINK: u32 = 0x00000100;

/// The handle is created in system process context and can only be accessed from kernel mode.
pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;

/// The routine opening the handle should enforce all access checks for the object,
/// even if the handle is being opened in kernel mode.
pub const OBJ_FORCE_ACCESS_CHECK: u32 = 0x00000400;

/// Separate device maps exists for each user in the system, and each user can manage
/// their own device maps. If this flag is set, the process user's device map is used
/// during impersonation instead of the impersonated user's device map.
pub const OBJ_IGNORE_IMPERSONATED_DEVICEMAP: u32 = 0x00000800;

/// If this flag is set, no reparse points will be followed when parsing the name of the associated object.
/// If any reparses are encountered the attempt will fail and return an `STATUS_REPARSE_POINT_ENCOUNTERED` result.
/// This can be used to determine if there are any reparse points in the object's path, in security scenarios.
pub const OBJ_DONT_REPARSE: u32 = 0x00001000;

/// Mask of valid object attribute flags.
pub const OBJ_VALID_ATTRIBUTES: u32 = 0x00001FF2;

/// The [`OBJECT_ATTRIBUTES`] structure specifies attributes that can be applied
/// to objects or object handles by routines that create objects and/or return handles to objects.
///
/// [`OBJECT_ATTRIBUTES`]: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[allow(missing_docs, non_camel_case_types, non_snake_case)]
pub struct OBJECT_ATTRIBUTES64 {
    pub Length: u32,                   // ULONG
    pub _pad1: u32,                    // (padding)
    pub RootDirectory: u64,            // HANDLE
    pub ObjectName: u64,               // PUNICODE_STRING
    pub Attributes: u32,               // ULONG
    pub _pad2: u32,                    // (padding)
    pub SecurityDescriptor: u64,       // PVOID
    pub SecurityQualityOfService: u64, // PVOID
}

impl OBJECT_ATTRIBUTES64 {
    /// Creates object attributes.
    ///
    /// Corresponds to `InitializeObjectAttributes(p, NULL, attributes, NULL, NULL)`.
    pub const fn new(attributes: u32) -> Self {
        Self {
            Length: size_of::<Self>() as u32,
            _pad1: 0,
            RootDirectory: 0,
            ObjectName: 0,
            Attributes: attributes,
            _pad2: 0,
            SecurityDescriptor: 0,
            SecurityQualityOfService: 0,
        }
    }
}

const _: () = assert!(size_of::<OBJECT_ATTRIBUTES64>() == 0x30);

/// The [`CLIENT_ID`] structure contains identifiers of a process and a thread.
///
/// [`CLIENT_ID`]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[allow(missing_docs, non_camel_case_types, non_snake_case)]
pub struct CLIENT_ID64 {
    pub UniqueProcess: u64, // HANDLE
    pub UniqueThread: u64,  // HANDLE
}

impl CLIENT_ID64 {
    /// Creates a client ID with only the process ID set.
    pub const fn process(pid: ProcessId) -> Self {
        Self {
            UniqueProcess: pid.0 as u64,
            UniqueThread: 0,
        }
    }
}

const _: () = assert!(size_of::<CLIENT_ID64>() == 0x10);

/// A [`LIST_ENTRY`] structure describes an entry in a doubly linked list or serves as the header for such a list.
///
/// [`LIST_ENTRY`]: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[allow(missing_docs, non_camel_case_types, non_snake_case)]
pub struct LIST_ENTRY64 {
    pub Flink: u64, // PLIST_ENTRY
    pub Blink: u64, // PLIST_ENTRY
}

impl LIST_ENTRY64 {
    /// Creates a list entry with null links.
    #[expect(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self { Flink: 0, Blink: 0 }
    }
}

const _: () = assert!(size_of::<LIST_ENTRY64>() == 0x10);

/// A `KAPC_STATE` structure contains information about the APC state of a thread.
///
/// # Notes
///
/// Windows 7 names the two flag bytes `KernelApcInProgress` and `UserApcPending`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[allow(missing_docs, non_camel_case_types, non_snake_case)]
pub struct KAPC_STATE64 {
    pub ApcListHead: [LIST_ENTRY64; 2], // LIST_ENTRY[2]
    pub Process: u64,                   // PKPROCESS
    pub InProgressFlags: u8,            // UCHAR
    pub KernelApcPending: u8,           // BOOLEAN
    pub UserApcPendingAll: u8,          // BOOLEAN
    pub _pad: [u8; 5],                  // (padding)
}

impl KAPC_STATE64 {
    /// Creates zeroed `KAPC_STATE`.
    #[expect(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            ApcListHead: [LIST_ENTRY64::new(), LIST_ENTRY64::new()],
            Process: 0,
            InProgressFlags: 0,
            KernelApcPending: 0,
            UserApcPendingAll: 0,
            _pad: [0; 5],
        }
    }
}

const _: () = assert!(size_of::<KAPC_STATE64>() == 0x30);
