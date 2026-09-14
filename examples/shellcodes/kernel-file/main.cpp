// The parameter buffer contains one NUL-terminated UTF-16 string: the NT path
// of the file to create, for example `\??\C:\Users\John\Desktop\test.txt`.
//
// The payload creates that file from kernel mode and writes "hello world" into
// it, then reports the terminal status through the bridge. It runs unchanged on
// a hijacked thread (call recipe) and on a spawned system thread (spawn
// recipe): the path buffer lives in the payload's own nonpaged allocation and
// the handle is a kernel handle, so neither depends on the process context.

#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

#include <vmi/shellcode.hpp>

#include <cstdint>

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(ZwClose);
        IMPORT_SYMBOL(ZwCreateFile);
        IMPORT_SYMBOL(ZwWriteFile);
IMPORT_END();

namespace sc {

enum class stage : uint8_t {
    none = 0x00,
    create = 0x01,
    write = 0x02,
};

enum class error : uint8_t {
    empty_path = 0x01,
    zw_create_file = 0x02,
    zw_write_file = 0x03,
};

template <>
struct vmi::is_error_code<error> : std::true_type {};

using failure = vmi::failure<error>;
using status = vmi::status<stage>;

struct bridge_traits : vmi::default_bridge_traits {
    static constexpr uint16_t request = 0x0002;
};

struct bridge : vmi::bridge<bridge_traits> {
    static constexpr uint16_t method_exit = 0xffff;

    static
    void
    exit(
        _In_ status status
        )
    {
        (void)send(
            method_exit,
            status.packed_status(),
            status.native_code()
            );
    }
};

auto
WriteHelloWorld(
    _In_ PCWSTR Path
    ) -> status
{
    //
    // Measure the path and describe it as a counted string.
    //

    SIZE_T PathLength = 0;
    while (Path[PathLength] != L'\0')
    {
        PathLength++;
    }

    if (PathLength == 0)
    {
        return status::invalid_parameters(
            stage::none,
            failure{ error::empty_path, STATUS_INVALID_PARAMETER }
            );
    }

    UNICODE_STRING FileName;
    FileName.Length = (USHORT)(PathLength * sizeof(WCHAR));
    FileName.MaximumLength = FileName.Length;
    FileName.Buffer = (PWSTR)Path;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    //
    // Create or truncate the file.
    //

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status = ZwCreateFile(&FileHandle,
                                   FILE_GENERIC_WRITE,
                                   &ObjectAttributes,
                                   &IoStatusBlock,
                                   NULL,
                                   FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ,
                                   FILE_OVERWRITE_IF,
                                   FILE_SYNCHRONOUS_IO_NONALERT
                                   | FILE_NON_DIRECTORY_FILE,
                                   NULL,
                                   0);

    if (!NT_SUCCESS(Status))
    {
        return status::operation_failed(
            stage::create,
            failure{ error::zw_create_file, Status }
            );
    }

    //
    // Write the content. The buffer lives on the kernel stack, which is safe
    // because FILE_SYNCHRONOUS_IO_NONALERT completes the write before
    // ZwWriteFile returns.
    //

    const char Content[] = "hello world";

    Status = ZwWriteFile(FileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &IoStatusBlock,
                         (PVOID)Content,
                         sizeof(Content) - 1,
                         NULL,
                         NULL);

    ZwClose(FileHandle);

    if (!NT_SUCCESS(Status))
    {
        return status::operation_failed(
            stage::write,
            failure{ error::zw_write_file, Status }
            );
    }

    return status::success(stage::write);
}

extern "C"
void
__fastcall
entry(
    _In_ void* argument1,
    _In_ void* argument2
    )
{
    (void)argument1; // Consumed by the scfw kernel-mode bootstrap.

    vmi::cursor parameters{ argument2 };

    bridge::exit(WriteHelloWorld(parameters.next_wstring()));
}

} // namespace sc
