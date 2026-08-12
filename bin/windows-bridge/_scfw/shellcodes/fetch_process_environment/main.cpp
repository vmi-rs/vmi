#pragma clang diagnostic ignored "-Wwritable-strings"

#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

#include "bridge.h"

#include <memory>

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#pragma region Definitions

#define WIN_MEMORY_TAG      'niWH'

#ifndef MAX_PATH
#define MAX_PATH            260
#endif // !MAX_PATH

#define MAX_DOS_DRIVES      26

#define KSECDDDECLSPEC
#define SEC_ENTRY           __stdcall

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

#define RTL_QUERY_REGISTRY_TYPECHECK 0x00000100 // Used with RTL_QUERY_REGISTRY_DIRECT to
                                                // validate the registry value type
                                                // expected by caller with actual type thats
                                                // read from the registry.

//
// Use the most significant byte of DefaultType from QueryTable, as the
// caller's expected REG_TYPE
//
#define RTL_QUERY_REGISTRY_TYPECHECK_SHIFT          24

#define MOUNTMGRCONTROLTYPE                         0x0000006D // 'm'
#define MOUNTDEVCONTROLTYPE                         0x0000004D // 'M'
#define IOCTL_MOUNTDEV_QUERY_DEVICE_NAME            CTL_CODE(MOUNTDEVCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUNTMGR_QUERY_POINTS                 CTL_CODE(MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MOUNTMGR_DEVICE_NAME                        L"\\Device\\MountPointManager"
#define MOUNTMGR_DOS_DEVICE_NAME                    L"\\\\.\\MountPointManager"

#undef NtCurrentPeb
#define NtCurrentPeb()                              PsGetProcessPeb(PsGetCurrentProcess())

#pragma endregion Definitions

//////////////////////////////////////////////////////////////////////////
// Internal Structures.
//////////////////////////////////////////////////////////////////////////

#pragma region Internal Structures

extern "C" {

typedef CCHAR KPROCESSOR_MODE;
typedef struct _ACCESS_STATE* PACCESS_STATE;
typedef struct _CALLBACK_OBJECT* PCALLBACK_OBJECT;
typedef struct _EPROCESS* PEPROCESS, *PKPROCESS, *PRKPROCESS;
typedef struct _ETHREAD* PETHREAD, *PKTHREAD, *PRKTHREAD;
typedef struct _IO_TIMER* PIO_TIMER;
typedef struct _KINTERRUPT* PKINTERRUPT;
typedef struct _OBJECT_TYPE* POBJECT_TYPE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
} POOL_TYPE;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef struct _OBJECT_HANDLE_INFORMATION {
    ULONG HandleAttributes;
    ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;

} // extern "C"

#pragma endregion Internal Structures

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

#pragma region Structures

extern "C" {

typedef struct _WIN_ENVIRONMENT_INSTALLATION_INFORMATION
{
    ULONG           CurrentMajorVersionNumber;
    ULONG           CurrentMinorVersionNumber;
    UNICODE_STRING  CurrentVersion;
    ULONG           InstallDate;
    ULONGLONG       InstallTime;
    UNICODE_STRING  ProductId;
    UNICODE_STRING  ProductName;
    UNICODE_STRING  RegisteredOwner;
    UNICODE_STRING  RegisteredOrganization;
    UNICODE_STRING  SystemDrive;
    UNICODE_STRING  SystemRoot;
} WIN_ENVIRONMENT_INSTALLATION_INFORMATION, *PWIN_ENVIRONMENT_INSTALLATION_INFORMATION;

typedef struct _WIN_ENVIRONMENT_DRIVE_INFORMATION
{
    UNICODE_STRING  DriveName;
    UNICODE_STRING  NtDrivePath;
    UNICODE_STRING  NtDevicePath;
    UNICODE_STRING  NtVolumeMountPointPath;
    UNICODE_STRING  VolumeLabel;
    ULONG           VolumeSerialNumber;
} WIN_ENVIRONMENT_DRIVE_INFORMATION, *PWIN_ENVIRONMENT_DRIVE_INFORMATION;

typedef struct _WIN_ENVIRONMENT
{
    UNICODE_STRING  UserName;
    UNICODE_STRING  DomainName;
    UNICODE_STRING  Sid;

    UNICODE_STRING  UserTempPath;

    UNICODE_STRING  ComputerName;
    UNICODE_STRING  MachineGuid;

    ULONG           DriveMap;
    WIN_ENVIRONMENT_DRIVE_INFORMATION DriveInformation[MAX_DOS_DRIVES];
    WIN_ENVIRONMENT_INSTALLATION_INFORMATION InstallationInformation;
} WIN_ENVIRONMENT, *PWIN_ENVIRONMENT;

typedef struct _WIN_PROCESS
{
    ULONG           ProcessId;
    ULONGLONG       ProcessObject;
    UNICODE_STRING  ImagePath;
    UNICODE_STRING  CommandLine;
    WIN_ENVIRONMENT Environment;
} WIN_PROCESS, *PWIN_PROCESS;

} // extern "C"

#pragma endregion Structures

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

#pragma region Function prototypes

extern "C" {

//
// Ex
//

NTKERNELAPI
PVOID
NTAPI
ExAllocatePoolWithTag (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePoolWithTag (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P,
    _In_ ULONG Tag
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePool (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P
    );

//
// Ke
//

_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeStackAttachProcess (
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
    );

_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeUnstackDetachProcess (
    _In_ PRKAPC_STATE ApcState
    );

//
// Ob
//

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
ObReferenceObjectByHandle (
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID *Object,
    _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer (
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

NTKERNELAPI
NTSTATUS
ObCloseHandle (
    _In_ _Post_ptr_invalid_ HANDLE Handle,
    _In_ KPROCESSOR_MODE PreviousMode
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
LONG_PTR
FASTCALL
ObfDereferenceObject (
    _In_ PVOID Object
    );

//
// Ps
//

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
PEPROCESS
PsGetCurrentProcess (
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
HANDLE
PsGetProcessId (
    _In_ PEPROCESS Process
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
PPEB
PsGetProcessPeb (
    _In_ PEPROCESS Process
    );

_IRQL_requires_max_(APC_LEVEL)
EXTERN_C
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId (
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
PACCESS_TOKEN
PsReferencePrimaryToken (
    _Inout_ PEPROCESS Process
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsDereferencePrimaryToken (
    _In_ PACCESS_TOKEN PrimaryToken
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
PsAcquireProcessExitSynchronization (
    _Inout_ PEPROCESS Process
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsReleaseProcessExitSynchronization (
    _Inout_ PEPROCESS Process
    );

//
// Rtl
//

_IRQL_requires_max_(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString (
    _Inout_ PUNICODE_STRING UnicodeString,
    _In_ PSID Sid,
    _In_ BOOLEAN AllocateDestinationString
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString (
    _Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_)
        PUNICODE_STRING UnicodeString
    );

//
// Se
//

NTSTATUS
SeLocateProcessImageName (
    _Inout_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING *pImageFileName
    );

//
// Sec
//

KSECDDDECLSPEC
NTSTATUS
SEC_ENTRY
SecLookupAccountSid (
    _In_      PSID Sid,
    _Out_     PULONG NameSize,
    _Inout_   PUNICODE_STRING NameBuffer,
    _Out_     PULONG DomainSize OPTIONAL,
    _Out_opt_ PUNICODE_STRING DomainBuffer OPTIONAL,
    _Out_     PSID_NAME_USE NameUse
    );

} // extern "C"

#pragma endregion Function prototypes

//////////////////////////////////////////////////////////////////////////
// System Table.
//////////////////////////////////////////////////////////////////////////

#pragma region System Table

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(ExAllocatePoolWithTag);
        IMPORT_SYMBOL(ExFreePoolWithTag);
        IMPORT_SYMBOL(ExFreePool);
        IMPORT_SYMBOL(KeStackAttachProcess);
        IMPORT_SYMBOL(KeUnstackDetachProcess);
        IMPORT_SYMBOL(ObReferenceObjectByHandle);
        IMPORT_SYMBOL(ObOpenObjectByPointer);
        IMPORT_SYMBOL(ObCloseHandle);
        IMPORT_SYMBOL(ObfDereferenceObject);
        IMPORT_SYMBOL(PsGetCurrentProcess);
        IMPORT_SYMBOL(PsGetProcessId);
        IMPORT_SYMBOL(PsGetProcessPeb);
        IMPORT_SYMBOL(PsLookupProcessByProcessId);
        IMPORT_SYMBOL(PsReferencePrimaryToken);
        IMPORT_SYMBOL(PsDereferencePrimaryToken);
        IMPORT_SYMBOL(PsAcquireProcessExitSynchronization);
        IMPORT_SYMBOL(PsReleaseProcessExitSynchronization);
        IMPORT_SYMBOL(RtlConvertSidToUnicodeString);
        IMPORT_SYMBOL(RtlCreateUnicodeString);
        IMPORT_SYMBOL(RtlUnicodeStringToAnsiString);
        IMPORT_SYMBOL(RtlDuplicateUnicodeString);
        IMPORT_SYMBOL(RtlEqualUnicodeString);
        IMPORT_SYMBOL(RtlFreeAnsiString);
        IMPORT_SYMBOL(RtlFreeUnicodeString);
        IMPORT_SYMBOL(RtlQueryRegistryValues);
        IMPORT_SYMBOL(SeLocateProcessImageName);
        IMPORT_SYMBOL(ZwDeviceIoControlFile);
        IMPORT_SYMBOL(ZwOpenFile);
        IMPORT_SYMBOL(ZwOpenKey);
        IMPORT_SYMBOL(ZwOpenSymbolicLinkObject);
        IMPORT_SYMBOL(ZwQueryInformationProcess);
        IMPORT_SYMBOL(ZwQueryInformationToken);
        IMPORT_SYMBOL(ZwQuerySystemInformation);
        IMPORT_SYMBOL(ZwQuerySymbolicLinkObject);
        IMPORT_SYMBOL(ZwQueryValueKey);
        IMPORT_SYMBOL(ZwQueryVolumeInformationFile);

        IMPORT_SYMBOL(SeTokenObjectType, POBJECT_TYPE*);

    IMPORT_MODULE("ksecdd.sys");
        IMPORT_SYMBOL(SecLookupAccountSid);
IMPORT_END();

#pragma endregion System Table

//////////////////////////////////////////////////////////////////////////
// CRT.
//////////////////////////////////////////////////////////////////////////

#pragma region CRT

_Check_return_ _Ret_maybenull_ _Post_writable_byte_size_(size)
void*
__cdecl
malloc(
    _In_ size_t size
    )
{
    return sc::ExAllocatePoolWithTag(NonPagedPool, size, WIN_MEMORY_TAG);
}

void
__cdecl
free(
    _Pre_maybenull_ _Post_invalid_ void* pointer
    )
{
    if (pointer == nullptr)
    {
        return;
    }

    sc::ExFreePoolWithTag(pointer, WIN_MEMORY_TAG);
}

void*
__cdecl
operator new (
    size_t size
    )
{
    return malloc(size);
}

void*
__cdecl
operator new[](
    size_t size
    )
{
    return malloc(size);
}

void
operator delete(
    void* pointer
    ) noexcept
{
    return free(pointer);
}

void
operator delete(
    void* pointer,
    size_t
    ) noexcept
{
    return free(pointer);
}

void
operator delete[](
    void* pointer
    ) noexcept
{
    return free(pointer);
}

void
operator delete[](
    void* pointer,
    size_t
    ) noexcept
{
    return free(pointer);
}

namespace sc {

class unique_handle
{
public:
    unique_handle() : value_{ nullptr } {}
    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;

    ~unique_handle()
    {
        if (value_ != nullptr)
        {
            ObCloseHandle(value_, KernelMode);
        }
    }

    operator HANDLE() const
    {
        return value_;
    }

    PHANDLE operator&()
    {
        return &value_;
    }

private:
    HANDLE value_;
};

class attached_process
{
public:
    attached_process() {}
    attached_process(_In_ PEPROCESS Process)
    {
        NTSTATUS Status;

        if (Process == PsGetCurrentProcess())
        {
            return;
        }

        Status = PsAcquireProcessExitSynchronization(Process);

        if (!NT_SUCCESS(Status))
        {
            return;
        }

        KeStackAttachProcess(Process, &apc_state_);
        attached_process_ = Process;
    }

    attached_process(const attached_process&) = delete;
    attached_process& operator=(const attached_process&) = delete;

    operator bool() const
    {
        return attached_process_ != nullptr;
    }

//    void reset(_In_ PEPROCESS Process)
//    {
//        if (attached_)
//        {
//            PsReleaseProcessExitSynchronization(attached_process_);
//            KeUnstackDetachProcess(&apc_state_);
//        }
//
//        attached_ = true;
//        KeStackAttachProcess(Process, &apc_state_);
//    }

    ~attached_process()
    {
        if (attached_process_)
        {
            PsReleaseProcessExitSynchronization(attached_process_);
            KeUnstackDetachProcess(&apc_state_);
        }
    }

private:
    KAPC_STATE apc_state_;
    PEPROCESS attached_process_ = nullptr;
};

} // namespace sc

#pragma endregion CRT

namespace sc {

NTSTATUS
EnvQueryUserName(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING UserName,
    _Out_ PUNICODE_STRING DomainName,
    _Out_ PUNICODE_STRING Sid
    );

NTSTATUS
EnvQueryUserTempPath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING UserTempPath
    );

NTSTATUS
EnvQueryDosDriveMap(
    _Out_ PULONG DriveMap
    );

NTSTATUS
EnvQueryComputerName(
    _Out_ PUNICODE_STRING ComputerName
    );

NTSTATUS
EnvQueryMachineGuid(
    _Out_ PUNICODE_STRING MachineGuid
    );

NTSTATUS
EnvQueryInstallationInformation(
    _Out_ PWIN_ENVIRONMENT_INSTALLATION_INFORMATION InstallationInformation
    );

VOID
EnvFreeInstallationInformation(
    _In_ PWIN_ENVIRONMENT_INSTALLATION_INFORMATION InstallationInformation
    );

NTSTATUS
EnvDrivePathToDevicePath(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_ PUNICODE_STRING NtDevicePath
    );

NTSTATUS
EnvDrivePathToVolumeInformation(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_opt_ PUNICODE_STRING VolumeLabel,
    _Out_opt_ PULONG VolumeSerialNumber
    );

NTSTATUS
EnvDevicePathToVolumeMountPointPath(
    _In_ PUNICODE_STRING NtDevicePath,
    _In_ PUNICODE_STRING NtVolumeMountPointPath
    );

NTSTATUS
EnvQueryDriveInformation(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_ PWIN_ENVIRONMENT_DRIVE_INFORMATION DriveInformation
    );

VOID
EnvFreeDriveInformation(
    _In_ PWIN_ENVIRONMENT_DRIVE_INFORMATION DriveInformation
    );

NTSTATUS
EnvAllocate(
    _Out_ PWIN_ENVIRONMENT WinEnvironment,
    _In_ PEPROCESS Process
    );

VOID
EnvFree(
    _In_ PWIN_ENVIRONMENT WinEnvironment
    );

NTSTATUS
EnvRtlQueryEnvironmentVariable_U(
    _In_opt_ PWSTR Environment,
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value
    );

NTSTATUS
EnvQueryEnvironmentVariable(
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value
    );

NTSTATUS
EnvQueryRegistryString(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING ValueContent
    );

NTSTATUS
WinProcessQueryParameters(
    _Out_ PWIN_PROCESS WinProcess,
    _In_ PEPROCESS Process
    );

NTSTATUS
WinProcessAllocate(
    _Out_ PWIN_PROCESS WinProcess,
    _In_ PEPROCESS Process
    );

VOID
WinProcessFree(
    _In_ PWIN_PROCESS WinProcess
    );

} // namespace sc

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

#pragma region Private functions

namespace sc {

NTSTATUS
EnvRtlQueryEnvironmentVariable_U(
    _In_opt_ PWSTR Environment,
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value
    )
{
    //
    // Equivalent to RtlQueryEnvironmentVariable_U().
    // Stolen from ReactOS.
    //

    NTSTATUS Status;
    PWSTR wcs;
    UNICODE_STRING var;
    PWSTR val;

    if (Environment == NULL)
    {
        PPEB Peb = NtCurrentPeb();

        if (Peb)
        {
            Environment = (PWSTR)Peb->ProcessParameters->Environment;
        }
    }

    if (Environment == NULL)
    {
        return STATUS_VARIABLE_NOT_FOUND;
    }

    Value->Length = 0;

    wcs = Environment;
    while (*wcs)
    {
        var.Buffer = wcs++;
        wcs = wcschr(wcs, L'=');

        if (wcs == NULL)
        {
            wcs = var.Buffer + wcslen(var.Buffer);
        }

        if (*wcs)
        {
            var.Length = var.MaximumLength = (USHORT)(wcs - var.Buffer) * sizeof(WCHAR);
            val = ++wcs;
            wcs += wcslen(wcs);

            if (RtlEqualUnicodeString(&var, Name, TRUE))
            {
                Value->Length = (USHORT)(wcs - val) * sizeof(WCHAR);

                if (Value->Length <= Value->MaximumLength)
                {
                    RtlCopyMemory(Value->Buffer,
                                  val,
                                  min(Value->Length + sizeof(WCHAR), Value->MaximumLength));

                    Status = STATUS_SUCCESS;
                }
                else
                {
                    Status = STATUS_BUFFER_TOO_SMALL;
                }

                return Status;
            }
        }
        wcs++;
    }

    return STATUS_VARIABLE_NOT_FOUND;
}

NTSTATUS
EnvQueryEnvironmentVariable(
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value
    )
{
    NTSTATUS Status;

    UNICODE_STRING TempValue{};
    auto TempValueBuffer = std::unique_ptr<std::byte[]>{};

    do
    {
        if (TempValue.Length)
        {
            TempValue.MaximumLength = TempValue.Length + sizeof(WCHAR);

            TempValueBuffer = std::make_unique<std::byte[]>(TempValue.MaximumLength);
            TempValue.Buffer = (PWCH)TempValueBuffer.get();
        }

        Status = EnvRtlQueryEnvironmentVariable_U(NULL,
                                                  Name,
                                                  &TempValue);

    } while (Status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return RtlDuplicateUnicodeString(0, &TempValue, Value);
}

NTSTATUS
EnvQueryRegistryString(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING ValueContent
    )
{
    NTSTATUS Status;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    unique_handle KeyHandle{};
    Status = ZwOpenKey(&KeyHandle,
                       GENERIC_READ,
                       &ObjectAttributes);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ULONG RequiredLength{};

    auto KeyValueInformationBuffer = std::unique_ptr<std::byte[]>{};
    ULONG KeyValueInformationLength{};

    do
    {
        if (RequiredLength)
        {
            KeyValueInformationBuffer = std::make_unique<std::byte[]>(RequiredLength);
            KeyValueInformationLength = (USHORT)(RequiredLength);
        }

        Status = ZwQueryValueKey(KeyHandle,
                                 ValueName,
                                 KeyValueFullInformation,
                                 KeyValueInformationBuffer.get(),
                                 KeyValueInformationLength,
                                 &RequiredLength);

    } while (Status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    auto KeyValueInformation = reinterpret_cast<PKEY_VALUE_FULL_INFORMATION>(KeyValueInformationBuffer.get());

    if (
        KeyValueInformation == NULL ||
        KeyValueInformation->Type != REG_SZ ||
        KeyValueInformation->DataLength > UNICODE_STRING_MAX_BYTES
        )
    {
        return STATUS_DATA_ERROR;
    }

    UNICODE_STRING KeyValue {
        .Length         = (USHORT)(KeyValueInformation->DataLength - sizeof(WCHAR)),
        .MaximumLength  = (USHORT)(KeyValueInformation->DataLength),
        .Buffer         = (PWCHAR)((ULONG_PTR)(KeyValueInformation) + KeyValueInformation->DataOffset),
    };

    return RtlDuplicateUnicodeString(0, &KeyValue, ValueContent);
}

}

#pragma endregion Private functions

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

#pragma region Public functions

namespace sc {

NTSTATUS
EnvQueryUserName(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING UserName,
    _Out_ PUNICODE_STRING DomainName,
    _Out_ PUNICODE_STRING Sid
    )
{
    //
    // Similar to GetUserName().
    //

    NTSTATUS Status;

    PACCESS_TOKEN AccessToken;
    AccessToken = PsReferencePrimaryToken(Process);

    unique_handle TokenHandle{};
    Status = ObOpenObjectByPointer(AccessToken,
                                   0,
                                   NULL,
                                   TOKEN_ALL_ACCESS,
                                   *SeTokenObjectType,
                                   (KPROCESSOR_MODE)KernelMode,
                                   &TokenHandle);

    PsDereferencePrimaryToken(AccessToken);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ULONG ReturnLength;
    SE_TOKEN_USER TokenUserInformation;
    Status = ZwQueryInformationToken(TokenHandle,
                                     TokenUser,
                                     &TokenUserInformation,
                                     static_cast<ULONG>(sizeof(TokenUserInformation)),
                                     &ReturnLength);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = RtlConvertSidToUnicodeString(Sid,
                                          TokenUserInformation.User.Sid,
                                          TRUE);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ULONG UserNameLength{};
    auto UserNameBuffer = std::unique_ptr<std::byte[]>{};

    ULONG DomainNameLength{};
    auto DomainNameBuffer = std::unique_ptr<std::byte[]>{};

    do
    {
        if (UserNameLength)
        {
            UserNameBuffer = std::make_unique<std::byte[]>(UserNameLength);
        }

        if (DomainNameLength)
        {
            DomainNameBuffer = std::make_unique<std::byte[]>(DomainNameLength);
        }

        UserName->Length = 0;
        UserName->MaximumLength = (USHORT)(UserNameLength);
        UserName->Buffer = (PWCHAR)UserNameBuffer.get();

        DomainName->Length = 0;
        DomainName->MaximumLength = (USHORT)(DomainNameLength);
        DomainName->Buffer = (PWCHAR)DomainNameBuffer.get();

        SID_NAME_USE NameUse;
        Status = SecLookupAccountSid(&TokenUserInformation.Sid,
                                     &UserNameLength,
                                     UserName,
                                     &DomainNameLength,
                                     DomainName,
                                     &NameUse);

    } while (Status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(Status))
    {
        UserName->Length = 0;
        UserName->MaximumLength = 0;
        UserName->Buffer = NULL;

        DomainName->Length = 0;
        DomainName->MaximumLength = 0;
        DomainName->Buffer = NULL;

        return Status;
    }

    UserNameBuffer.release();
    DomainNameBuffer.release();

    return Status;
}

NTSTATUS
EnvQueryUserTempPath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING UserTempPath
    )
{
    //
    // Similar to GetTempPath().
    //

    NTSTATUS Status;

    attached_process attached{ Process };

    if (!attached)
    {
    Default:
        UNICODE_STRING WindowsDirectory;
        RtlInitUnicodeString(&WindowsDirectory, _(L"C:\\WINDOWS\\"));
        return RtlDuplicateUnicodeString(0, &WindowsDirectory, UserTempPath);
    }

    UNICODE_STRING EnvironmentValueName;

    RtlInitUnicodeString(&EnvironmentValueName, _(L"TMP"));
    Status = EnvQueryEnvironmentVariable(&EnvironmentValueName, UserTempPath);

    if (NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&EnvironmentValueName, _(L"TEMP"));
    Status = EnvQueryEnvironmentVariable(&EnvironmentValueName, UserTempPath);

    if (NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&EnvironmentValueName, _(L"USERPROFILE"));
    Status = EnvQueryEnvironmentVariable(&EnvironmentValueName, UserTempPath);

    if (NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    goto Default;
}

NTSTATUS
EnvQueryDosDriveMap(
    _Out_ PULONG DriveMap
    )
{
    //
    // Similar to GetLogicalDrives().
    //

    NTSTATUS Status;

    ULONG ReturnLength;
    PROCESS_DEVICEMAP_INFORMATION DeviceMapInformation;
    Status = ZwQueryInformationProcess(ZwCurrentProcess(),
                                       ProcessDeviceMap,
                                       &DeviceMapInformation.Query,
                                       static_cast<ULONG>(sizeof(DeviceMapInformation.Query)),
                                       &ReturnLength);

    if (NT_SUCCESS(Status))
    {
        *DriveMap = DeviceMapInformation.Query.DriveMap;
    }

    return Status;
}

NTSTATUS
EnvQueryComputerName(
    _Out_ PUNICODE_STRING ComputerName
    )
{
    //
    // Similar to GetComputerName().
    //

    NTSTATUS Status;

    UNICODE_STRING ValueName;
    RtlInitUnicodeString(&ValueName, _(L"ComputerName"));

    UNICODE_STRING RegistryPath;
    RtlInitUnicodeString(&RegistryPath, _(L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName"));
    Status = EnvQueryRegistryString(&RegistryPath, &ValueName, ComputerName);

    if (NT_SUCCESS(Status))
    {
        return Status;
    }

    RtlInitUnicodeString(&RegistryPath, _(L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\ComputerName\\ComputerName"));
    return EnvQueryRegistryString(&RegistryPath, &ValueName, ComputerName);
}

NTSTATUS
EnvQueryMachineGuid(
    _Out_ PUNICODE_STRING MachineGuid
    )
{
    UNICODE_STRING RegistryPath;
    RtlInitUnicodeString(&RegistryPath, _(L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\Cryptography"));

    UNICODE_STRING ValueName;
    RtlInitUnicodeString(&ValueName, _(L"MachineGuid"));

    return EnvQueryRegistryString(&RegistryPath, &ValueName, MachineGuid);
}

NTSTATUS
EnvQueryInstallationInformation(
    _Out_ PWIN_ENVIRONMENT_INSTALLATION_INFORMATION InstallationInformation
    )
{
    NTSTATUS Status;

    RTL_QUERY_REGISTRY_TABLE QueryTable[11] = {
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT /* | RTL_QUERY_REGISTRY_REQUIRED */ | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"CurrentMajorVersionNumber"),
            .EntryContext = &InstallationInformation->CurrentMajorVersionNumber,
            .DefaultType = REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT /* | RTL_QUERY_REGISTRY_REQUIRED */ | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"CurrentMinorVersionNumber"),
            .EntryContext = &InstallationInformation->CurrentMinorVersionNumber,
            .DefaultType = REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"CurrentVersion"),
            .EntryContext = &InstallationInformation->CurrentVersion,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"InstallDate"),
            .EntryContext = &InstallationInformation->InstallDate,
            .DefaultType = REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            //
            // Nonstring data with size, in bytes, > sizeof(ULONG)
            //
            // The buffer pointed to by EntryContext must begin with a signed LONG value.
            // The magnitude of the value must specify the size, in bytes, of the buffer.
            // If the sign of the value is negative, RtlQueryRegistryValues will only store
            // the data of the key value.  Otherwise, it will use the first ULONG in the
            // buffer to record the value length, in bytes, the second ULONG to record the
            // value type, and the rest of the buffer to store the value data.
            //
            // (ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
            //

            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT /* | RTL_QUERY_REGISTRY_REQUIRED */ | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"InstallTime"),
            .EntryContext = &InstallationInformation->InstallTime,
            .DefaultType = REG_QWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"ProductId"),
            .EntryContext = &InstallationInformation->ProductId,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"ProductName"),
            .EntryContext = &InstallationInformation->ProductName,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"RegisteredOwner"),
            .EntryContext = &InstallationInformation->RegisteredOwner,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"RegisteredOrganization"),
            .EntryContext = &InstallationInformation->RegisteredOrganization,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            .QueryRoutine = NULL,
            .Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_TYPECHECK,
            .Name = _(L"SystemRoot"),
            .EntryContext = &InstallationInformation->SystemRoot,
            .DefaultType = REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        },
        {
            //
            // End of table.
            //
        }
    };

    //
    // See the comment above for the meaning of the negative value.
    //

    *((PLONG)&InstallationInformation->InstallTime) = -(LONG)(sizeof(InstallationInformation->InstallTime));

    Status = RtlQueryRegistryValues(RTL_REGISTRY_WINDOWS_NT,
                                    _(L""),
                                    QueryTable,
                                    NULL,
                                    NULL);


    if (!NT_SUCCESS(Status))
    {
        EnvFreeInstallationInformation(InstallationInformation);
        return Status;
    }

    //
    // SystemDrive is created from SystemRoot.
    //

    //NT_ASSERT(
    //    InstallationInformation->SystemRoot.Length >= 2 &&
    //    InstallationInformation->SystemRoot.Buffer[2] == L'\\'
    //);

    //
    // Temporarily cut the string after 2 characters.
    //

    InstallationInformation->SystemRoot.Buffer[2] = UNICODE_NULL;

    Status = RtlCreateUnicodeString(&InstallationInformation->SystemDrive,
                                    InstallationInformation->SystemRoot.Buffer)
        ? STATUS_SUCCESS
        : STATUS_INSUFFICIENT_RESOURCES;

    if (!NT_SUCCESS(Status))
    {
        EnvFreeInstallationInformation(InstallationInformation);
        return Status;
    }

    //
    // Return back the backslash ('\\').
    //

    InstallationInformation->SystemRoot.Buffer[2] = L'\\';

    return STATUS_SUCCESS;
}

VOID
EnvFreeInstallationInformation(
    _In_ PWIN_ENVIRONMENT_INSTALLATION_INFORMATION InstallationInformation
    )
{
    InstallationInformation->CurrentMajorVersionNumber = 0;
    InstallationInformation->CurrentMinorVersionNumber = 0;
    RtlFreeUnicodeString(&InstallationInformation->CurrentVersion);
    InstallationInformation->InstallDate = 0;
    InstallationInformation->InstallTime = 0;
    RtlFreeUnicodeString(&InstallationInformation->ProductId);
    RtlFreeUnicodeString(&InstallationInformation->ProductName);
    RtlFreeUnicodeString(&InstallationInformation->RegisteredOwner);
    RtlFreeUnicodeString(&InstallationInformation->RegisteredOrganization);
    RtlFreeUnicodeString(&InstallationInformation->SystemDrive);
    RtlFreeUnicodeString(&InstallationInformation->SystemRoot);
}

NTSTATUS
EnvDrivePathToDevicePath(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_ PUNICODE_STRING NtDevicePath
    )
{
    //
    // Similar to QueryDosDevice().
    //

    NTSTATUS Status;

    //
    // Drop backslash to open volume.
    //

    UNICODE_STRING FixedNtDrivePath;
    FixedNtDrivePath = *NtDrivePath;

    if (FixedNtDrivePath.Buffer[(FixedNtDrivePath.Length / sizeof(WCHAR)) - 1] == L'\\')
    {
        FixedNtDrivePath.Length -= sizeof(WCHAR);
    }

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               &FixedNtDrivePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    unique_handle DeviceHandle{};
    Status = ZwOpenSymbolicLinkObject(&DeviceHandle,
                                      SYMBOLIC_LINK_QUERY,
                                      &ObjectAttributes);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ULONG RequiredLength{};
    auto NtDevicePathBuffer = std::unique_ptr<std::byte[]>{};

    do
    {
        if (RequiredLength)
        {
            NtDevicePathBuffer = std::make_unique<std::byte[]>(RequiredLength);
        }

        NtDevicePath->Length = 0;
        NtDevicePath->MaximumLength = (USHORT)(RequiredLength);
        NtDevicePath->Buffer = (PWCHAR)NtDevicePathBuffer.get();

        Status = ZwQuerySymbolicLinkObject(DeviceHandle,
                                           NtDevicePath,
                                           &RequiredLength);

    } while (Status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(Status))
    {
        NtDevicePath->Length = 0;
        NtDevicePath->MaximumLength = 0;
        NtDevicePath->Buffer = NULL;

        return Status;
    }

    NtDevicePathBuffer.release();

    return Status;
}

NTSTATUS
EnvDrivePathToVolumeInformation(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_opt_ PUNICODE_STRING VolumeLabel,
    _Out_opt_ PULONG VolumeSerialNumber
    )
{
    //
    // Similar to GetVolumeInformation().
    //

    NTSTATUS Status;

    if (VolumeLabel == NULL && VolumeSerialNumber == NULL)
    {
        //
        // Nothing to do.
        //

        return STATUS_SUCCESS;
    }

    //
    // Get VolumeInfo.
    //

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               NtDrivePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);


    unique_handle VolumeHandle{};
    IO_STATUS_BLOCK IoStatusBlock;
    Status = ZwOpenFile(&VolumeHandle,
                        SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        0,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    auto VolumeInformationBuffer = std::unique_ptr<std::byte[]>{};
    ULONG VolumeInformationSize{};

    do
    {
        auto VolumeInformation = reinterpret_cast<PFILE_FS_VOLUME_INFORMATION>(VolumeInformationBuffer.get());

        if (!VolumeInformation)
        {
            VolumeInformationSize = sizeof(FILE_FS_VOLUME_INFORMATION);
        }
        else
        {
            VolumeInformationSize = sizeof(FILE_FS_VOLUME_INFORMATION) + VolumeInformation->VolumeLabelLength + sizeof(WCHAR);
        }

        VolumeInformationBuffer = std::make_unique<std::byte[]>(VolumeInformationSize);

        Status = ZwQueryVolumeInformationFile(VolumeHandle,
                                              &IoStatusBlock,
                                              VolumeInformationBuffer.get(),
                                              VolumeInformationSize,
                                              FileFsVolumeInformation);

    } while (Status == STATUS_BUFFER_OVERFLOW && VolumeLabel != NULL);

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
    {
        return Status;
    }

    auto VolumeInformation = reinterpret_cast<PFILE_FS_VOLUME_INFORMATION>(VolumeInformationBuffer.get());

    if (Status != STATUS_BUFFER_OVERFLOW && VolumeLabel != NULL)
    {
        UNICODE_STRING VolumeInformationLabel{
            .Length         = (USHORT)(VolumeInformation->VolumeLabelLength),
            .MaximumLength  = (USHORT)(VolumeInformation->VolumeLabelLength),
            .Buffer         = VolumeInformation->VolumeLabel,
        };

        Status = RtlDuplicateUnicodeString(0, &VolumeInformationLabel, VolumeLabel);
    }

    if (VolumeSerialNumber)
    {
        *VolumeSerialNumber = VolumeInformation->VolumeSerialNumber;
    }

    return Status;
}

NTSTATUS
EnvDevicePathToVolumeMountPointPath(
    _In_ PUNICODE_STRING NtDevicePath,
    _In_ PUNICODE_STRING NtVolumeMountPointPath
    )
{
    //
    // Similar to GetVolumeNameForVolumeMountPoint().
    //

    NTSTATUS Status;

    UNICODE_STRING MountMgrPath;
    RtlInitUnicodeString(&MountMgrPath, _(MOUNTMGR_DEVICE_NAME));

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               &MountMgrPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    unique_handle MountMgrHandle{};
    IO_STATUS_BLOCK IoStatusBlock;
    Status = ZwOpenFile(&MountMgrHandle,
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_ALERT);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // Set up the mount point structure.
    //

    ULONG MountPointLength = sizeof(MOUNTMGR_MOUNT_POINT) + NtDevicePath->Length;
    auto MountPointBuffer = std::make_unique<std::byte[]>(MountPointLength);
    auto MountPoint = reinterpret_cast<PMOUNTMGR_MOUNT_POINT>(MountPointBuffer.get());
    MountPoint->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    MountPoint->DeviceNameLength = NtDevicePath->Length;
    RtlCopyMemory(&MountPoint[1], NtDevicePath->Buffer, NtDevicePath->Length);

    //
    // Set up the mount points structure.
    //

    ULONG MountPointsLength{};
    auto MountPointsBuffer = std::unique_ptr<std::byte[]>{};
    auto MountPoints = reinterpret_cast<PMOUNTMGR_MOUNT_POINTS>(MountPointsBuffer.get());

    do
    {
        if (!MountPoints)
        {
            MountPointsLength = sizeof(MOUNTMGR_MOUNT_POINTS);
        }
        else
        {
            MountPointsLength = MountPoints->Size;
        }

        MountPointsBuffer = std::make_unique<std::byte[]>(MountPointsLength);

        MountPoints = reinterpret_cast<PMOUNTMGR_MOUNT_POINTS>(MountPointsBuffer.get());
        MountPoints->Size = MountPointLength;

        Status = ZwDeviceIoControlFile(MountMgrHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &IoStatusBlock,
                                       IOCTL_MOUNTMGR_QUERY_POINTS,
                                       MountPoint,
                                       MountPointLength,
                                       MountPoints,
                                       MountPointsLength);

    } while (Status == STATUS_BUFFER_OVERFLOW);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    for (
        ULONG MountPointIndex = 0;
        MountPointIndex < MountPoints->NumberOfMountPoints;
        MountPointIndex += 1
        )
    {
        UNICODE_STRING SymbolicLink{
            .Length         = MountPoints->MountPoints[MountPointIndex].SymbolicLinkNameLength,
            .MaximumLength  = MountPoints->MountPoints[MountPointIndex].SymbolicLinkNameLength,
            .Buffer         = (PWCH)((ULONG_PTR)MountPoints + MountPoints->MountPoints[MountPointIndex].SymbolicLinkNameOffset),
        };

        //
        // If that's a NT volume name (GUID form), keep it!
        //

        if (MOUNTMGR_IS_NT_VOLUME_NAME(&SymbolicLink))
        {
            return RtlDuplicateUnicodeString(0, &SymbolicLink, NtVolumeMountPointPath);
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS
EnvQueryDriveInformation(
    _In_ PUNICODE_STRING NtDrivePath,
    _Out_ PWIN_ENVIRONMENT_DRIVE_INFORMATION DriveInformation
    )
{
    NTSTATUS Status;

    //
    // "\\??\\C:\\" -> "C:"
    //

    UNICODE_STRING TempDriveName = *NtDrivePath;
    TempDriveName.Buffer += 4; // sizeof("\\??\\") - 1
    TempDriveName.Length = 2 * sizeof(WCHAR);
    TempDriveName.MaximumLength = 2 * sizeof(WCHAR);

    Status = RtlDuplicateUnicodeString(0, &TempDriveName, &DriveInformation->DriveName);

    if (!NT_SUCCESS(Status))
    {
        EnvFreeDriveInformation(DriveInformation);
        return Status;
    }

    Status = RtlDuplicateUnicodeString(0, NtDrivePath, &DriveInformation->NtDrivePath);

    if (!NT_SUCCESS(Status))
    {
        EnvFreeDriveInformation(DriveInformation);
        return Status;
    }

    Status = EnvDrivePathToDevicePath(NtDrivePath,
                                      &DriveInformation->NtDevicePath);

    if (!NT_SUCCESS(Status))
    {
        EnvFreeDriveInformation(DriveInformation);
        return Status;
    }

    Status = EnvDrivePathToVolumeInformation(NtDrivePath,
                                             &DriveInformation->VolumeLabel,
                                             &DriveInformation->VolumeSerialNumber);

    if (!NT_SUCCESS(Status))
    {
        EnvFreeDriveInformation(DriveInformation);
        return Status;
    }

    Status = EnvDevicePathToVolumeMountPointPath(&DriveInformation->NtDevicePath,
                                                 &DriveInformation->NtVolumeMountPointPath);

    if (!NT_SUCCESS(Status))
    {
        EnvFreeDriveInformation(DriveInformation);
        return Status;
    }

    return STATUS_SUCCESS;
}

VOID
EnvFreeDriveInformation(
    _In_ PWIN_ENVIRONMENT_DRIVE_INFORMATION DriveInformation
    )
{
    RtlFreeUnicodeString(&DriveInformation->DriveName);
    RtlFreeUnicodeString(&DriveInformation->NtDrivePath);
    RtlFreeUnicodeString(&DriveInformation->NtDevicePath);
    RtlFreeUnicodeString(&DriveInformation->NtVolumeMountPointPath);
    RtlFreeUnicodeString(&DriveInformation->VolumeLabel);
    DriveInformation->VolumeSerialNumber = 0;
}

NTSTATUS
EnvAllocate(
    _Out_ PWIN_ENVIRONMENT WinEnvironment,
    _In_ PEPROCESS Process
    )
{
    NTSTATUS Status;

    UNICODE_STRING NtDrivePath;
    RtlInitUnicodeString(&NtDrivePath, _(L"\\??\\A:\\"));

    //
    // First perform queries that depend on current process.
    //

    Status = EnvQueryUserName(Process,
                              &WinEnvironment->UserName,
                              &WinEnvironment->DomainName,
                              &WinEnvironment->Sid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = EnvQueryUserTempPath(Process,
                                  &WinEnvironment->UserTempPath);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = EnvQueryDosDriveMap(&WinEnvironment->DriveMap);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    //
    // Finally, query values that are independent of current process.
    //

    Status = EnvQueryComputerName(&WinEnvironment->ComputerName);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = EnvQueryMachineGuid(&WinEnvironment->MachineGuid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = EnvQueryInstallationInformation(&WinEnvironment->InstallationInformation);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    for (ULONG DriveIndex = 0; DriveIndex < MAX_DOS_DRIVES; DriveIndex += 1)
    {
        if (WinEnvironment->DriveMap & (1 << DriveIndex))
        {
            NtDrivePath.Buffer[4] = L'A' + (UCHAR)(DriveIndex);

            Status = EnvQueryDriveInformation(&NtDrivePath,
                                              &WinEnvironment->DriveInformation[DriveIndex]);

            if (!NT_SUCCESS(Status))
            {
                break;
            }
        }
    }

Exit:
    if (!NT_SUCCESS(Status))
    {
        EnvFree(WinEnvironment);
    }

    return Status;
}

VOID
EnvFree(
    _In_ PWIN_ENVIRONMENT WinEnvironment
    )
{
    RtlFreeUnicodeString(&WinEnvironment->UserName);
    RtlFreeUnicodeString(&WinEnvironment->DomainName);
    RtlFreeUnicodeString(&WinEnvironment->Sid);

    RtlFreeUnicodeString(&WinEnvironment->UserTempPath);

    RtlFreeUnicodeString(&WinEnvironment->ComputerName);
    RtlFreeUnicodeString(&WinEnvironment->MachineGuid);

    WinEnvironment->DriveMap = 0;

    for (ULONG DriveIndex = 0; DriveIndex < MAX_DOS_DRIVES; DriveIndex += 1)
    {
        EnvFreeDriveInformation(&WinEnvironment->DriveInformation[DriveIndex]);
    }

    EnvFreeInstallationInformation(&WinEnvironment->InstallationInformation);
}

NTSTATUS
WinProcessQueryImagePath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImagePath
    )
{
    NTSTATUS Status;

    PUNICODE_STRING TempFileName;
    Status = SeLocateProcessImageName(Process, &TempFileName);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = RtlDuplicateUnicodeString(0, TempFileName, ImagePath);

    ExFreePool(TempFileName);

    return Status;
}

NTSTATUS
WinProcessQueryCommandLine(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING CommandLine
    )
{
    attached_process attached{ Process };

    if (!attached)
    {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    PPEB Peb = NtCurrentPeb();
    if (!Peb)
    {
        return STATUS_NOT_FOUND;
    }

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = Peb->ProcessParameters;
    if (!ProcessParameters)
    {
        return STATUS_NOT_FOUND;
    }

    return RtlDuplicateUnicodeString(0, &ProcessParameters->CommandLine, CommandLine);
}

NTSTATUS
WinProcessAllocate(
    _Out_ PWIN_PROCESS WinProcess,
    _In_ PEPROCESS Process
    )
{
    NTSTATUS Status;

    WinProcess->ProcessId = (ULONG)(ULONG_PTR)(PsGetProcessId(Process));
    WinProcess->ProcessObject = (ULONGLONG)(ULONG_PTR)Process;

    //
    // Status is intentionally ignored here.
    // If these two functions fail, then simply ImagePath and CommandLine
    // will be empty.
    //

    Status = WinProcessQueryImagePath(Process, &WinProcess->ImagePath);
    Status = WinProcessQueryCommandLine(Process, &WinProcess->CommandLine);

    return EnvAllocate(&WinProcess->Environment, Process);
}

VOID
WinProcessFree(
    _In_ PWIN_PROCESS WinProcess
    )
{
    EnvFree(&WinProcess->Environment);
    RtlFreeUnicodeString(&WinProcess->CommandLine);
    RtlFreeUnicodeString(&WinProcess->ImagePath);
}

} // namespace sc

#pragma endregion Public functions

//////////////////////////////////////////////////////////////////////////
// Main.
//////////////////////////////////////////////////////////////////////////

#pragma region Main

namespace sc {

struct bridge
    : common_bridge<BRIDGE_REQUEST_FETCH_PROCESS_ENVIRONMENT>
{
    static constexpr uint32_t RESPONSE_CONTINUE             = 0x00000000;
    static constexpr uint32_t RESPONSE_ABORT                = 0xFFFFFFFF;

    static constexpr uint16_t METHOD_BEGIN                  = 0x0001;
    static constexpr uint16_t METHOD_END                    = 0x0002;
    static constexpr uint16_t METHOD_FETCH_EVIRONMENT       = 0x0003;

    static constexpr uint16_t ERROR_INVOCATION_FAILED_MASK  = 0x0100;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_MASK  = 0x0200;

    //
    // General errors.
    //

    static constexpr uint16_t ERROR_ABORT = 0xFFFF;

    //
    // Invocation errors.
    //

    static constexpr uint16_t ERROR_INVOCATION_FAILED_PSLOOKUPPROCESSBYPROCESSID = ERROR_INVOCATION_FAILED_MASK | 0x01;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ZWQUERYSYSTEMINFORMATION = ERROR_INVOCATION_FAILED_MASK | 0x02;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_WINPROCESSALLOCATE = ERROR_INVOCATION_FAILED_MASK | 0x03;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_SERIALIZEINTERNAL = ERROR_INVOCATION_FAILED_MASK | 0x04;

    static
    void
    begin(
        void
        )
    {
        request(METHOD_BEGIN);
    }

    static
    void
    end(
        void
        )
    {
        request(METHOD_END);
    }

    static
    void
    fetch_environment(
        _In_ void* buffer,
        _In_ size_t length
        )
    {
        request(METHOD_FETCH_EVIRONMENT, uintptr_t(buffer), uintptr_t(length));
    }
};

VOID
SerializeBOOLEAN(
    _Inout_ PVOID* Cursor,
    _In_ BOOLEAN Value
    )
{
    PVOID CapturedCursor = *Cursor;

    RtlCopyMemory(CapturedCursor, &Value, sizeof(Value));
    CapturedCursor = (PVOID)((ULONG_PTR)CapturedCursor + sizeof(Value));

    *Cursor = CapturedCursor;
}

VOID
SerializeULONG(
    _Inout_ PVOID* Cursor,
    _In_ ULONG Value
    )
{
    PVOID CapturedCursor = *Cursor;

    RtlCopyMemory(CapturedCursor, &Value, sizeof(Value));
    CapturedCursor = (PVOID)((ULONG_PTR)CapturedCursor + sizeof(Value));

    *Cursor = CapturedCursor;
}

VOID
SerializeULONGLONG(
    _Inout_ PVOID* Cursor,
    _In_ ULONGLONG Value
    )
{
    PVOID CapturedCursor = *Cursor;

    RtlCopyMemory(CapturedCursor, &Value, sizeof(Value));
    CapturedCursor = (PVOID)((ULONG_PTR)CapturedCursor + sizeof(Value));

    *Cursor = CapturedCursor;
}


NTSTATUS
SerializeUnicodeString(
    _Inout_ PVOID* Cursor,
    _In_ PUNICODE_STRING UnicodeString
    )
{
    NTSTATUS Status;
    PVOID CapturedCursor = *Cursor;

    ANSI_STRING AnsiString;
    Status = RtlUnicodeStringToAnsiString(&AnsiString, UnicodeString, TRUE);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    RtlCopyMemory(CapturedCursor, &AnsiString.Length, sizeof(USHORT));
    CapturedCursor = (PVOID)((ULONG_PTR)CapturedCursor + sizeof(USHORT));

    RtlCopyMemory(CapturedCursor, AnsiString.Buffer, AnsiString.Length);
    CapturedCursor = (PVOID)((ULONG_PTR)CapturedCursor + AnsiString.Length);

    RtlFreeAnsiString(&AnsiString);

    *Cursor = CapturedCursor;

    return STATUS_SUCCESS;
}

NTSTATUS
SerializeInternal(
    _In_ PEPROCESS Process
    )
{
    NTSTATUS Status;

    ULONG TotalLength = 0;
    PVOID Buffer = NULL;
    PVOID Cursor = NULL;

    WIN_PROCESS WinProcess = { 0 };
    Status = WinProcessAllocate(&WinProcess, Process);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    TotalLength = 0;
    TotalLength += sizeof(WinProcess.ProcessId);
    TotalLength += sizeof(WinProcess.ProcessObject);

    TotalLength += sizeof(USHORT) + WinProcess.ImagePath.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.CommandLine.Length / sizeof(WCHAR);

    TotalLength += sizeof(USHORT) + WinProcess.Environment.UserName.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.DomainName.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.Sid.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.UserTempPath.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.ComputerName.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.MachineGuid.Length / sizeof(WCHAR);
    TotalLength += sizeof(WinProcess.Environment.DriveMap);
    for (ULONG DriveIndex = 0; DriveIndex < MAX_DOS_DRIVES; DriveIndex += 1)
    {
        if (WinProcess.Environment.DriveMap & (1 << DriveIndex))
        {
            TotalLength += sizeof(USHORT) + WinProcess.Environment.DriveInformation[DriveIndex].DriveName.Length / sizeof(WCHAR);
            TotalLength += sizeof(USHORT) + WinProcess.Environment.DriveInformation[DriveIndex].NtDrivePath.Length / sizeof(WCHAR);
            TotalLength += sizeof(USHORT) + WinProcess.Environment.DriveInformation[DriveIndex].NtDevicePath.Length / sizeof(WCHAR);
            TotalLength += sizeof(USHORT) + WinProcess.Environment.DriveInformation[DriveIndex].NtVolumeMountPointPath.Length / sizeof(WCHAR);
            TotalLength += sizeof(USHORT) + WinProcess.Environment.DriveInformation[DriveIndex].VolumeLabel.Length / sizeof(WCHAR);
            TotalLength += sizeof(WinProcess.Environment.DriveInformation[DriveIndex].VolumeSerialNumber);
        }
    }
    TotalLength += sizeof(WinProcess.Environment.InstallationInformation.CurrentMajorVersionNumber);
    TotalLength += sizeof(WinProcess.Environment.InstallationInformation.CurrentMinorVersionNumber);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.CurrentVersion.Length / sizeof(WCHAR);
    TotalLength += sizeof(WinProcess.Environment.InstallationInformation.InstallDate);
    TotalLength += sizeof(WinProcess.Environment.InstallationInformation.InstallTime);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.ProductId.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.ProductName.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.RegisteredOwner.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.RegisteredOrganization.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.SystemDrive.Length / sizeof(WCHAR);
    TotalLength += sizeof(USHORT) + WinProcess.Environment.InstallationInformation.SystemRoot.Length / sizeof(WCHAR);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, TotalLength, WIN_MEMORY_TAG);
    if (!Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Cursor = Buffer;

#define ENV_CHECK(Status) do { if (!NT_SUCCESS(Status)) { goto Exit; } } while (0)

    SerializeULONG(&Cursor, WinProcess.ProcessId);
    SerializeULONGLONG(&Cursor, WinProcess.ProcessObject);

    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.ImagePath));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.CommandLine));

    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.UserName));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DomainName));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.Sid));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.UserTempPath));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.ComputerName));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.MachineGuid));
    SerializeULONG(&Cursor, WinProcess.Environment.DriveMap);
    for (ULONG DriveIndex = 0; DriveIndex < MAX_DOS_DRIVES; DriveIndex += 1)
    {
        if (WinProcess.Environment.DriveMap & (1 << DriveIndex))
        {
            ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DriveInformation[DriveIndex].DriveName));
            ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DriveInformation[DriveIndex].NtDrivePath));
            ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DriveInformation[DriveIndex].NtDevicePath));
            ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DriveInformation[DriveIndex].NtVolumeMountPointPath));
            ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.DriveInformation[DriveIndex].VolumeLabel));
            SerializeULONG(&Cursor, WinProcess.Environment.DriveInformation[DriveIndex].VolumeSerialNumber);
        }
    }
    SerializeULONG(&Cursor, WinProcess.Environment.InstallationInformation.CurrentMajorVersionNumber);
    SerializeULONG(&Cursor, WinProcess.Environment.InstallationInformation.CurrentMinorVersionNumber);
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.CurrentVersion));
    SerializeULONG(&Cursor, WinProcess.Environment.InstallationInformation.InstallDate);
    SerializeULONGLONG(&Cursor, WinProcess.Environment.InstallationInformation.InstallTime);
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.ProductId));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.ProductName));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.RegisteredOwner));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.RegisteredOrganization));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.SystemDrive));
    ENV_CHECK(SerializeUnicodeString(&Cursor, &WinProcess.Environment.InstallationInformation.SystemRoot));

Exit:
    WinProcessFree(&WinProcess);

    if (NT_SUCCESS(Status))
    {
        bridge::fetch_environment(Buffer, TotalLength);
    }
    else
    {
        bridge::error(bridge::ERROR_INVOCATION_FAILED_WINPROCESSALLOCATE, Status, uintptr_t(Process));
    }

    if (Buffer)
    {
        ExFreePoolWithTag(Buffer, WIN_MEMORY_TAG);
    }

    return Status;
}

NTSTATUS
Serialize(
    _In_ PEPROCESS Process
    )
{
    return SerializeInternal(Process);
}

NTSTATUS
SerializeAllProcesses(
    VOID
    )
{
    NTSTATUS Status;

    const ULONG BUFFER_INCREMENT = 65536;

    auto SystemInformationBuffer = std::unique_ptr<std::byte[]>{};
    ULONG SystemInformationLength{};

    bridge::begin();

    do
    {
        SystemInformationLength += BUFFER_INCREMENT;
        SystemInformationBuffer  = std::make_unique<std::byte[]>(SystemInformationLength);

        Status = ZwQuerySystemInformation(SystemProcessInformation,
                                          SystemInformationBuffer.get(),
                                          SystemInformationLength,
                                          NULL);
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(Status))
    {
        bridge::error(bridge::ERROR_INVOCATION_FAILED_ZWQUERYSYSTEMINFORMATION,
                      Status);

        bridge::end();

        return Status;
    }

    PSYSTEM_PROCESS_INFORMATION SystemInformation;
    ULONG Offset = 0;
    ULONG Index = 0;

    do
    {
        SystemInformation = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(&SystemInformationBuffer[Offset]);

        PEPROCESS Process;
        Status = PsLookupProcessByProcessId(SystemInformation->UniqueProcessId,
                                            &Process);

        if (!NT_SUCCESS(Status))
        {
            bridge::error(bridge::ERROR_INVOCATION_FAILED_PSLOOKUPPROCESSBYPROCESSID,
                          Status,
                          uintptr_t(SystemInformation->UniqueProcessId));
            goto Next;
        }

        Status = SerializeInternal(Process);

        if (!NT_SUCCESS(Status))
        {
            bridge::error(bridge::ERROR_INVOCATION_FAILED_SERIALIZEINTERNAL,
                          Status,
                          uintptr_t(SystemInformation->UniqueProcessId));
        }

        ObfDereferenceObject(Process);

    Next:
        Offset += SystemInformation->NextEntryOffset;
        Index += 1;
    } while (SystemInformation->NextEntryOffset);

    bridge::end();

    return STATUS_SUCCESS;
}

} // namespace sc

#pragma endregion Main

namespace sc {

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;

    NTSTATUS Status;

    PEPROCESS ProcessObject = (PEPROCESS)argument2;

    if (ProcessObject != NULL)
    {
        Status = Serialize(ProcessObject);
    }
    else
    {
        Status = SerializeAllProcesses();
    }

    bridge::exit(Status);
}

} // namespace sc
