#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

#include "bridge.h"
#include "result.h"

#include <cstdint>
#include <optional>

extern "C" {

//////////////////////////////////////////////////////////////////////////
// Kernel definitions not provided by the Windows SDK.
//////////////////////////////////////////////////////////////////////////

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
} POOL_TYPE;

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

NTKERNELAPI
PVOID
NTAPI
ExAllocatePoolWithTag(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePoolWithTag(
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P,
    _In_ ULONG Tag
    );

NTKERNELAPI
NTSTATUS
ObCloseHandle(
    _In_ _Post_ptr_invalid_ HANDLE Handle,
    _In_ KPROCESSOR_MODE PreviousMode
    );

_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
NTAPI
MmCopyMemory(
    _In_ PVOID TargetAddress,
    _In_ MM_COPY_ADDRESS SourceAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Flags,
    _Out_ PSIZE_T NumberOfBytesTransferred
    );

} // extern "C"

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(ExAllocatePoolWithTag);
        IMPORT_SYMBOL(ExFreePoolWithTag);
        IMPORT_SYMBOL(MmCopyMemory);
        IMPORT_SYMBOL(ObCloseHandle);
        IMPORT_SYMBOL(ZwCreateSection);
        IMPORT_SYMBOL(ZwMapViewOfSection);
        IMPORT_SYMBOL(ZwQueryInformationFile);
        IMPORT_SYMBOL(ZwUnmapViewOfSection);
IMPORT_END();

namespace sc {

#define SHELLCODE_MEMORY_TAG 'tfcs'

enum class stage : uint8_t {
    none = 0x00,
    file_name = 0x01,
    file_size = 0x02,
    mapping = 0x03,
    buffer = 0x04,
    transfer = 0x05,
};

enum class error : uint8_t {
    ex_allocate_pool_with_tag = 0x01,
    mm_copy_memory = 0x02,
    zw_query_information_file = 0x03,
    zw_create_section = 0x04,
    zw_map_view_of_section = 0x05,
    bridge_begin = 0x06,
    invalid_chunk_size = 0x07,
};

template <>
struct proto::is_error_code<error> : std::true_type {};

using failure = proto::failure<error>;
using result = proto::result<stage>;

struct bridge_traits: proto::bridge::default_client_traits {
    static constexpr uint16_t request = 0x0003;
};

using bridge_client = proto::bridge::client<bridge_traits>;

enum class transfer_status : uint8_t {
    success = 0x00,
    error = 0xff,
};

struct bridge: bridge_client {
    static constexpr uint16_t method_begin = 0x0001;
    static constexpr uint16_t method_set_buffer = 0x0002;
    static constexpr uint16_t method_chunk = 0x0003;
    static constexpr uint16_t method_close = 0x0004;
    static constexpr uint16_t method_exit = 0xffff;

    static constexpr uintptr_t response_continue = 0x00000000;
    static constexpr uintptr_t response_abort = 0xffffffff;

    _Success_(return != 0)
    static
    ULONG
    begin(
        _In_ HANDLE FileHandle,
        _In_ LONGLONG FileSize,
        _In_ const UNICODE_STRING* FileName,
        _Out_ PULONG ChunkSize
        )
    {
        const auto response =
            bridge_client::send(
                method_begin,
                reinterpret_cast<uintptr_t>(FileHandle),
                static_cast<uintptr_t>(FileSize),
                reinterpret_cast<uintptr_t>(FileName->Buffer),
                static_cast<uintptr_t>(FileName->Length)
                );

        if (!response)
        {
            return 0;
        }

        *ChunkSize = (ULONG)(response->value1 >> 12);
        return (ULONG)(response->value1 & 0xfff);
    }

    static
    uintptr_t
    set_buffer(
        _In_ ULONG TransferHandle,
        _In_ PVOID Buffer
        )
    {
        const auto response = bridge_client::send(
            method_set_buffer,
            TransferHandle,
            reinterpret_cast<uintptr_t>(Buffer)
            );

        return response
            ? response->value1
            : response_abort;
    }

    static
    uintptr_t
    chunk(
        _In_ ULONG TransferHandle,
        _In_ ULONG Length
        )
    {
        const auto response = bridge_client::send(
            method_chunk,
            TransferHandle,
            static_cast<uintptr_t>(Length)
            );

        return response
            ? response->value1
            : response_abort;
    }

    static
    void
    close(
        _In_ ULONG TransferHandle,
        _In_ transfer_status Status
        )
    {
        (void)bridge_client::send(
            method_close,
            TransferHandle,
            static_cast<uintptr_t>(Status)
            );
    }

    static
    void
    exit(
        _In_ result result
        )
    {
        (void)bridge_client::send(
            method_exit,
            result.packed_status(),
            result.native_code()
            );
    }
};

auto
TransferFile(
    _In_ HANDLE FileHandle
    ) -> result
{
    NTSTATUS Status;

    //
    // Query the file name.
    //

    IO_STATUS_BLOCK IoStatusBlock;
    FILE_NAME_INFORMATION PartialFileNameInformation;
    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &PartialFileNameInformation,
                                    sizeof(PartialFileNameInformation),
                                    ::FileNameInformation);

    if (Status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(Status))
    {
        return result::operation_failed(
            stage::file_name,
            failure{ error::zw_query_information_file, Status }
            );
    }

    //
    // Allocate the full file name buffer and repeat the query.
    //


    PFILE_NAME_INFORMATION FileNameInformation;
    ULONG FileNameInformationSize =
        FIELD_OFFSET(FILE_NAME_INFORMATION, FileName)
        + PartialFileNameInformation.FileNameLength;

    do
    {
        FileNameInformation = (PFILE_NAME_INFORMATION)
            ExAllocatePoolWithTag(NonPagedPool,
                                  FileNameInformationSize,
                                  SHELLCODE_MEMORY_TAG);

        if (!FileNameInformation)
        {
            return result::operation_failed(
                stage::file_name,
                failure{
                    error::ex_allocate_pool_with_tag,
                    STATUS_INSUFFICIENT_RESOURCES
                    }
                );
        }

        Status = ZwQueryInformationFile(FileHandle,
                                        &IoStatusBlock,
                                        FileNameInformation,
                                        FileNameInformationSize,
                                        ::FileNameInformation);

        if (Status == STATUS_BUFFER_OVERFLOW)
        {
            //
            // Retry if a concurrent rename increases the required buffer size.
            //

            FileNameInformationSize =
                FIELD_OFFSET(FILE_NAME_INFORMATION, FileName)
                + FileNameInformation->FileNameLength;

            ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);
        }
    } while (Status == STATUS_BUFFER_OVERFLOW);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);

        return result::operation_failed(
            stage::file_name,
            failure{ error::zw_query_information_file, Status }
            );
    }

    UNICODE_STRING FileName;
    FileName.Length = (USHORT)FileNameInformation->FileNameLength;
    FileName.MaximumLength = FileName.Length;
    FileName.Buffer = FileNameInformation->FileName;

    //
    // Query the file size.
    //

    FILE_STANDARD_INFORMATION FileStandardInformation;
    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &FileStandardInformation,
                                    sizeof(FileStandardInformation),
                                    ::FileStandardInformation);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);

        return result::operation_failed(
            stage::file_size,
            failure{ error::zw_query_information_file, Status }
            );
    }

    LONGLONG FileSize = FileStandardInformation.EndOfFile.QuadPart;

    //
    // Map the file into the current process. OBJ_KERNEL_HANDLE keeps the
    // temporary section handle out of the current process's user handle table.
    // Empty files intentionally fail with STATUS_MAPPED_FILE_SIZE_ZERO.
    //

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    HANDLE SectionHandle;
    Status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ,
                             &ObjectAttributes,
                             NULL,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             FileHandle);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);

        return result::operation_failed(
            stage::mapping,
            failure{ error::zw_create_section, Status }
            );
    }

    PVOID BaseAddress = NULL;
    SIZE_T ViewSize = 0;
    Status = ZwMapViewOfSection(SectionHandle,
                                ZwCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);

    //
    // The mapped view keeps the section alive after its handle is closed.
    //

    ObCloseHandle(SectionHandle, KernelMode);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);

        return result::operation_failed(
            stage::mapping,
            failure{ error::zw_map_view_of_section, Status }
            );
    }

    //
    // Open the host transfer with the file metadata.
    //

    result result = result::success(stage::none);

    PVOID TransferBuffer;
    ULONG ChunkSize;
    ULONG TransferHandle = bridge::begin(FileHandle, FileSize, &FileName, &ChunkSize);

    if (!TransferHandle)
    {
        result = result::operation_failed(
            stage::transfer,
            failure{ error::bridge_begin }
            );

        goto CleanupMappedView;
    }

    if (!ChunkSize)
    {
        result = result::operation_failed(
            stage::buffer,
            failure{
                error::invalid_chunk_size,
                STATUS_INVALID_BUFFER_SIZE
                }
            );

        bridge::close(TransferHandle, transfer_status::error);
        goto CleanupMappedView;
    }

    //
    // Allocate the shared nonpaged chunk buffer.
    //

    TransferBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                           (SIZE_T)ChunkSize,
                                           SHELLCODE_MEMORY_TAG);

    if (!TransferBuffer)
    {
        result = result::operation_failed(
            stage::buffer,
            failure{
                error::ex_allocate_pool_with_tag,
                STATUS_INSUFFICIENT_RESOURCES
                }
            );

        bridge::close(TransferHandle, transfer_status::error);
        goto CleanupMappedView;
    }

    //
    // Publish the buffer and transfer the file one chunk at a time.
    //

    if (bridge::set_buffer(TransferHandle, TransferBuffer)
        != bridge::response_continue)
    {
        result = result::aborted(stage::buffer);
        bridge::close(TransferHandle, transfer_status::error);
        goto CleanupTransferBuffer;
    }

    for (LONGLONG Offset = 0; Offset < FileSize; Offset += ChunkSize)
    {
        LONGLONG Remaining = FileSize - Offset;
        ULONG Length = (ULONG)(Remaining < ChunkSize ? Remaining : ChunkSize);

        MM_COPY_ADDRESS SourceAddress;
        SourceAddress.VirtualAddress = (UCHAR*)BaseAddress + (SIZE_T)Offset;

        SIZE_T BytesCopied;
        Status = MmCopyMemory(TransferBuffer,
                              SourceAddress,
                              (SIZE_T)Length,
                              MM_COPY_MEMORY_VIRTUAL,
                              &BytesCopied);

        if (!NT_SUCCESS(Status))
        {
            result = result::operation_failed(
                stage::transfer,
                failure{ error::mm_copy_memory, Status }
                );

            bridge::close(TransferHandle, transfer_status::error);
            goto CleanupTransferBuffer;
        }

        if (bridge::chunk(TransferHandle, Length)
            != bridge::response_continue)
        {
            result = result::aborted(stage::transfer);
            bridge::close(TransferHandle, transfer_status::error);
            goto CleanupTransferBuffer;
        }
    }

    bridge::close(TransferHandle, transfer_status::success);
    result = result::success(stage::transfer);

    //
    // Release acquired resources in reverse order.
    //

CleanupTransferBuffer:
    ExFreePoolWithTag(TransferBuffer, SHELLCODE_MEMORY_TAG);

CleanupMappedView:
    ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);

CleanupFileName:
    ExFreePoolWithTag(FileNameInformation, SHELLCODE_MEMORY_TAG);

    //
    // Return the terminal result.
    //

Exit:
    return result;
}

extern "C"
void
__fastcall
entry(
    _In_ void* argument1,
    _In_ void* argument2
    )
{
    (void)argument1; // Consumed by the SCFW kernel-mode bootstrap.

    bridge::exit(TransferFile(reinterpret_cast<HANDLE>(argument2)));
}

} // namespace sc
