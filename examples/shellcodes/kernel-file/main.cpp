// Kernel-mode shellcode to create a file and write "hello world" into it.
//
// The parameter buffer contains a UTF-16 string representing the file path,
// for example `\??\C:\Users\John\Desktop\test.txt`.

#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

#include <vmi/shellcode.hpp>

#include <cstdint>

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(ZwCreateFile);
        IMPORT_SYMBOL(ZwWriteFile);
        IMPORT_SYMBOL(ZwClose);
IMPORT_END();

namespace sc {

//
// The stages of the shellcode's operation.
// Used to track the progress of the shellcode via bridge status codes.
//

enum class stage : uint8_t {
    none = 0x00,
    create = 0x01,
    write = 0x02,
};

//
// The error codes used by the shellcode to indicate specific failure.
//

enum class error : uint8_t {
    empty_path = 0x01,
    zw_create_file = 0x02,
    zw_write_file = 0x03,
};

//
// Specialization to indicate that `error` is an error code type.
//

template <>
struct vmi::is_error_code<error> : std::true_type {};

//
// The type used to represent a failure in the shellcode.
//

using failure = vmi::failure<error>;

//
// The type used to represent the status of the shellcode's operation.
//

using status = vmi::status<stage>;

struct bridge_traits : vmi::default_bridge_traits {
    //
    // The request code used by the bridge to identify this shellcode.
    //
    // This value is arbitrary but must match the request code expected
    // by the receiving side.
    //
    // See `KernelFileBridge::REQUEST` in
    //     examples/windows-shellcode/kernel_file/bridge.rs
    //

    static constexpr uint16_t request = 0x0002;
};

struct bridge : vmi::bridge<bridge_traits> {
    //
    // The method code used by the bridge to identify the exit method.
    //
    // Similarly to the request code, this value is also arbitrary but
    // must match the method code expected by the receiving side.
    //

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
    NTSTATUS Status;

    //
    // Determine the length of the path string.
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
    Status = ZwCreateFile(&FileHandle,
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
    // Write the content.
    //

    const CHAR Content[] = "hello world";

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
    (void)argument1; // Used only by the scfw kernel-mode bootstrap.

    vmi::cursor parameters{ argument2 };

    bridge::exit(WriteHelloWorld(parameters.next_wstring()));
}

} // namespace sc
