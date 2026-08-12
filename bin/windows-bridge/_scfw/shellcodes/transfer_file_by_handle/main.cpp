#pragma clang diagnostic ignored "-Wwritable-strings"

#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

#include "bridge.h"

//
// Processor modes.
//

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
} POOL_TYPE;

EXTERN_C
PVOID
NTAPI
ExAllocatePoolWithTag (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

EXTERN_C
VOID
ExFreePoolWithTag (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P,
    _In_ ULONG Tag
    );

EXTERN_C
NTSTATUS
ObCloseHandle (
    _In_ _Post_ptr_invalid_ HANDLE Handle,
    _In_ KPROCESSOR_MODE PreviousMode
    );

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(ExAllocatePoolWithTag);
        IMPORT_SYMBOL(ExFreePoolWithTag);
        IMPORT_SYMBOL(ObCloseHandle);
        IMPORT_SYMBOL(ZwQueryObject);
        IMPORT_SYMBOL(ZwQueryInformationFile);
        IMPORT_SYMBOL(ZwCreateSection);
        IMPORT_SYMBOL(ZwMapViewOfSection);
        IMPORT_SYMBOL(ZwUnmapViewOfSection);
IMPORT_END();

#define SC_POOL_TAG 'tPcS'

struct bridge
    : common_bridge<BRIDGE_REQUEST_TRANSFER_FILE_BY_HANDLE>
{
    static constexpr uint32_t RESPONSE_CONTINUE             = 0x00000000;
    static constexpr uint32_t RESPONSE_ABORT                = 0xFFFFFFFF;

    static constexpr uint16_t METHOD_TRANSFER_BEGIN         = 0x0001;
    static constexpr uint16_t METHOD_TRANSFER_SET_BUFFER    = 0x0002;
    static constexpr uint16_t METHOD_TRANSFER_PROGRESS      = 0x0003;
    static constexpr uint16_t METHOD_TRANSFER_END           = 0x0004;

    static constexpr uint16_t STATUS_TRANSFER_SUCCESS       = 0x0000;
    static constexpr uint16_t STATUS_TRANSFER_FAILED        = 0xFFFF;

    static constexpr uint16_t ERROR_INVOCATION_FAILED_MASK  = 0x0100;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_MASK  = 0x0200;

    //
    // General errors.
    //

    static constexpr uint16_t ERROR_ABORT = 0xFFFF;

    //
    // Invocation errors.
    //

    static constexpr uint16_t ERROR_INVOCATION_FAILED_ZWQUERYOBJECT          = ERROR_INVOCATION_FAILED_MASK | 0x01;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ZWQUERYINFORMATIONFILE = ERROR_INVOCATION_FAILED_MASK | 0x02;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ZWCREATESECTION        = ERROR_INVOCATION_FAILED_MASK | 0x03;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ZWMAPVIEWOFSECTION     = ERROR_INVOCATION_FAILED_MASK | 0x04;

    static
    uint32_t
    transfer_begin(
        _In_ PVOID FileHandle,
        _In_ LONGLONG FileSize,
        _In_ PUNICODE_STRING FileName,
        _Out_ PULONG ChunkSize
        )
    {
        const uint32_t result = static_cast<uint32_t>(
            request(METHOD_TRANSFER_BEGIN,
                    uintptr_t(FileHandle),
                    uintptr_t(FileSize),
                    uintptr_t(FileName->Buffer),
                    uintptr_t(FileName->Length))
                .value_or(RESPONSE_ABORT)
            );

        if (result == RESPONSE_ABORT)
        {
            *ChunkSize = 0;
            return RESPONSE_ABORT;
        }

        *ChunkSize = result >> 12;
        return result & 0xFFF;
    }

    static
    uint32_t
    transfer_set_buffer(
        _In_ ULONG TransferHandle,
        _In_ PVOID Buffer
        )
    {
        return static_cast<uint32_t>(
            request(METHOD_TRANSFER_SET_BUFFER,
                    uintptr_t(TransferHandle),
                    uintptr_t(Buffer))
                .value_or(RESPONSE_ABORT)
            );
    }

    static
    uint32_t
    transfer_progress(
        _In_ ULONG TransferHandle,
        _In_ SIZE_T Length
        )
    {
        return static_cast<uint32_t>(
            request(METHOD_TRANSFER_PROGRESS,
                    uintptr_t(TransferHandle),
                    uintptr_t(Length))
                .value_or(RESPONSE_ABORT)
            );
    }

    static
    uint32_t
    transfer_end(
        _In_ ULONG TransferHandle,
        _In_ ULONG Status
        )
    {
        return static_cast<uint32_t>(
            request(METHOD_TRANSFER_END,
                    uintptr_t(TransferHandle),
                    uintptr_t(Status))
                .value_or(RESPONSE_ABORT)
            );
    }
};

namespace sc {

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;
    PVOID FileHandle = argument2;

    //
    // Check if the synchronization leaf is supported by the hypervisor.
    //

    NTSTATUS Status;

    //
    // Query the file name.
    //

    ULONG ReturnLength = 0;
    ULONG ObjectInformationLength = 0;
    POBJECT_NAME_INFORMATION ObjectInformation = NULL;

    do
    {
        if (ReturnLength)
        {
            if (ObjectInformation)
            {
                ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);
            }

            ObjectInformation = (POBJECT_NAME_INFORMATION)
                                ExAllocatePoolWithTag(NonPagedPool,
                                                      ReturnLength,
                                                      SC_POOL_TAG);

            if (!ObjectInformation)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            ObjectInformationLength = ReturnLength;
        }

        Status = ZwQueryObject(FileHandle,
                               ObjectNameInformation,
                               ObjectInformation,
                               ObjectInformationLength,
                               &ReturnLength);

    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(Status) || !ObjectInformation)
    {
        if (ObjectInformation)
        {
            ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);
        }

        bridge::exit(bridge::ERROR_INVOCATION_FAILED_ZWQUERYOBJECT, Status);
        return;
    }

    //
    // Query the file size.
    //

    FILE_STANDARD_INFORMATION FileInformation;
    IO_STATUS_BLOCK IoStatusBlock;
    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &FileInformation,
                                    static_cast<ULONG>(sizeof(FileInformation)),
                                    FileStandardInformation);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);
        bridge::exit(bridge::ERROR_INVOCATION_FAILED_ZWQUERYINFORMATIONFILE, Status);
        return;
    }

    //
    // Map the file into the current process.
    //

    HANDLE SectionHandle;
    Status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ,
                             NULL,
                             NULL,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             FileHandle);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);
        bridge::exit(bridge::ERROR_INVOCATION_FAILED_ZWCREATESECTION, Status);
        return;
    }

    PVOID BaseAddress = NULL;
    SIZE_T ViewSize = 0;
    Status = ZwMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewShare,
                                0,
                                PAGE_READONLY);

    if (!NT_SUCCESS(Status))
    {
        ObCloseHandle(SectionHandle, KernelMode);
        ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);
        bridge::exit(bridge::ERROR_INVOCATION_FAILED_ZWMAPVIEWOFSECTION, Status);
        return;
    }

    //
    // Transfer the file content to the host.
    //

    LONGLONG FileSize = FileInformation.EndOfFile.QuadPart;

    ULONG ChunkSize;
    PVOID TransferBuffer;
    ULONG TransferHandle = bridge::transfer_begin(FileHandle, FileSize, &ObjectInformation->Name, &ChunkSize);

    if (TransferHandle == 0 || TransferHandle == bridge::RESPONSE_ABORT)
    {
        goto Cleanup2;
    }

    if (ChunkSize == 0)
    {
        bridge::transfer_end(TransferHandle, bridge::STATUS_TRANSFER_FAILED);
        goto Cleanup2;
    }

    //
    // Allocate a buffer for the transfer.
    //

    TransferBuffer = ExAllocatePoolWithTag(NonPagedPool, ChunkSize, SC_POOL_TAG);
    if (!TransferBuffer)
    {
        bridge::transfer_end(TransferHandle, bridge::STATUS_TRANSFER_FAILED);
        goto Cleanup2;
    }

    if (bridge::transfer_set_buffer(TransferHandle, TransferBuffer) != bridge::RESPONSE_CONTINUE)
    {
        goto Cleanup1;
    }

    for (LONGLONG Cursor = 0; Cursor < FileSize; Cursor += ChunkSize)
    {
        SIZE_T Length = (SIZE_T)min(ChunkSize, FileSize - Cursor);
        RtlCopyMemory(TransferBuffer,
                      (PVOID)((ULONG_PTR)BaseAddress + Cursor),
                      Length);

        if (bridge::transfer_progress(TransferHandle, Length) != bridge::RESPONSE_CONTINUE)
        {
            goto Cleanup1;
        }
    }

    //
    // Clean up.
    //

    bridge::transfer_end(TransferHandle, bridge::STATUS_TRANSFER_SUCCESS);

Cleanup1:
    ExFreePoolWithTag(TransferBuffer, SC_POOL_TAG);

Cleanup2:
    ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    ObCloseHandle(SectionHandle, KernelMode);
    ExFreePoolWithTag(ObjectInformation, SC_POOL_TAG);

    bridge::exit(0);
}

} // namespace sc
