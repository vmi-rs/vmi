//////////////////////////////////////////////////////////////////////////
// Pull shellcode protocol and execution model.
//////////////////////////////////////////////////////////////////////////
//
// This shellcode receives a packed parameter buffer through entry's first
// argument. It waits for the bridge host, validates the flags, expands the
// requested paths, and runs the enabled stages in this order:
//
//   entry(argument1)
//          |
//          v
//   wait for initial host gate
//          |
//          v
//   parse parameters and validate flags
//          |
//          v
//   expand paths and initialize COM
//          |
//          v
//   download  --->  extract  --->  execute
//      optional       optional       optional
//          |
//          v
//   report the terminal result to the bridge host
//
// Extraction consumes the downloaded file, so extract requires download.
// Execution may follow download and extraction, or run independently.
//
// Parameter wire format
// ---------------------
//
// The buffer has no length field, offsets table, or padding. Fields are
// consumed consecutively. Integers are little-endian. Strings are
// NUL-terminated UTF-16LE sequences, including no byte or character count.
//
//   +-------------------------------------------------------------+
//   | uint32_t flags                                              |
//   +-------------------------------------------------------------+
//   | if flags.download:                                          |
//   |   wchar_t url[]                                             |
//   |   wchar_t download_path[]                                   |
//   +-------------------------------------------------------------+
//   | if flags.extract:                                           |
//   |   wchar_t extraction_directory[]                            |
//   +-------------------------------------------------------------+
//   | if flags.execute:                                           |
//   |   wchar_t executable_path[]                                 |
//   |   if flags.arguments:                                       |
//   |     wchar_t arguments[]                                     |
//   |   if flags.working_directory:                               |
//   |     wchar_t working_directory[]                             |
//   |   if flags.show_window:                                     |
//   |     int32_t show_window                                     |
//   +-------------------------------------------------------------+
//
// Flag bits
// ---------
//
//   extract             0x00000001  Extract the downloaded archive.
//   execute             0x00000002  Execute executable_path.
//   download            0x00000004  Download url to download_path.
//   arguments           0x00000100  Append the arguments string.
//   working_directory   0x00000200  Append a working-directory string.
//   show_window         0x00000400  Append an explicit show-window value.
//
// arguments, working_directory, and show_window are invalid without execute.
// Unknown flag bits are invalid. No placeholder is encoded for an absent
// optional field: the next enabled field follows immediately. With no flags,
// the complete buffer consists only of the uint32_t flags value.
//
// Path and stage behavior
// -----------------------
//
// Environment variables are expanded in download_path,
// extraction_directory, executable_path, and working_directory. The URL and
// arguments are passed through unchanged. If working_directory is absent, the
// parent of the expanded executable path is used; if there is no parent, the
// current directory is left to Windows. If show_window is absent,
// SW_SHOWNORMAL is used.
//
// Download creates the destination's parent directory. A failed download is
// reported to the bridge host with its attempt number and HRESULT; a continue
// response retries it, while an abort response terminates the request.
// Extraction waits for a host gate, creates the output directory, and uses
// Shell.Application to copy archive items. Execution waits for its host gate
// and invokes ShellExecuteExW.
//
// The parser retains pointers into the supplied buffer and performs no bounds,
// string-length, or string-content checks. The caller is responsible for
// supplying values accepted by the relevant Windows APIs and must keep the
// complete, correctly encoded buffer alive until entry returns.
//

#define SCFW_ENABLE_LOAD_MODULE
#define SCFW_ENABLE_UNLOAD_MODULE
#define SCFW_ENABLE_LOOKUP_SYMBOL
#define SCFW_ENABLE_FULL_MODULE_SEARCH
#define SCFW_MODULE_DEFAULT_FLAGS ( \
    SCFW_FLAG_DYNAMIC_LOAD        \
    | SCFW_FLAG_DYNAMIC_UNLOAD    \
    | SCFW_FLAG_DYNAMIC_RESOLVE   \
    )

#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

#include "bridge.h"
#include "enum_flags.h"
#include "reader.h"
#include "result.h"

#include <concepts>
#include <cstdint>
#include <expected>
#include <type_traits>
#include <initguid.h>
#include <shldisp.h>
#include <shellapi.h>
#include <shlobj.h>
#include <urlmon.h>
#include <windows.h>

IMPORT_BEGIN();
    IMPORT_MODULE("kernel32.dll");
        IMPORT_SYMBOL(Sleep);
        IMPORT_SYMBOL(ExpandEnvironmentStringsW);

    IMPORT_MODULE("shell32.dll");
        IMPORT_SYMBOL(SHCreateDirectoryExW);
        IMPORT_SYMBOL(ShellExecuteExW);

    IMPORT_MODULE("ole32.dll");
        IMPORT_SYMBOL(CoInitializeEx);
        IMPORT_SYMBOL(CoUninitialize);
        IMPORT_SYMBOL(CoCreateInstance);

    IMPORT_MODULE("oleaut32.dll");
        IMPORT_SYMBOL(VariantInit);
        IMPORT_SYMBOL(VariantClear);
        IMPORT_SYMBOL(SysAllocString);

    IMPORT_MODULE("urlmon.dll");
        IMPORT_SYMBOL(URLDownloadToFileW);
IMPORT_END();

namespace sc {

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

// {13709620-C279-11CE-A49E-444553540000}
DEFINE_GUID(CLSID_Shell, 0x13709620, 0xC279, 0x11CE, 0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);

// {D8F015C0-C278-11CE-A49E-444553540000}
DEFINE_GUID(IID_IShellDispatch, 0xD8F015C0, 0xC278, 0x11CE, 0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);

// Bridge protocol signatures encoded as little-endian ASCII.
constexpr uint32_t  BRIDGE_MAGIC = 0x42494d56;             // "VMIB"
constexpr uint16_t  PULL_REQUEST = 0x0001;
constexpr uintptr_t BRIDGE_VERIFY_VALUE3 = 0x213353522d494d56; // "VMI-RS3!"
constexpr uintptr_t BRIDGE_VERIFY_VALUE4 = 0x213453522d494d56; // "VMI-RS4!"

constexpr uint16_t method_download = 0x0001;
constexpr uint16_t method_extract = 0x0002;
constexpr uint16_t method_execute = 0x0003;
constexpr uint16_t method_exit = 0xffff;

constexpr uintptr_t response_continue = 0x00000000;
constexpr uintptr_t response_abort = 0xffffffff;

constexpr DWORD bridge_wait_milliseconds = 250;
constexpr DWORD extraction_poll_milliseconds = 100;
constexpr uint32_t extraction_poll_limit = 600;
constexpr LONG extract_copy_options =
    FOF_SILENT
    | FOF_NOCONFIRMATION
    | FOF_NOCONFIRMMKDIR
    | FOF_NOERRORUI;

enum class parameter_flags : uint32_t {
    none                    = 0x00000000,
    extract                 = 0x00000001,
    execute                 = 0x00000002,
    download                = 0x00000004,
    arguments               = 0x00000100,
    working_directory       = 0x00000200,
    show_window             = 0x00000400,
};

SCFW_DEFINE_ENUM_FLAG_OPERATORS(parameter_flags);

constexpr parameter_flags execute_flags =
    parameter_flags::arguments
    | parameter_flags::working_directory
    | parameter_flags::show_window;

constexpr parameter_flags valid_flags =
    parameter_flags::extract
    | parameter_flags::execute
    | parameter_flags::download
    | execute_flags;

enum class stage : uint8_t {
    none                    = 0x00,
    parameters              = 0x01,
    initialization          = 0x02,
    download                = 0x03,
    extract                 = 0x04,
    execute                 = 0x05,
};

using bridge_client = proto::bridge::client<
    &proto::bridge::bridge_xen_vmcall,
    BRIDGE_MAGIC,
    PULL_REQUEST,
    BRIDGE_VERIFY_VALUE3,
    BRIDGE_VERIFY_VALUE4
    >;

using proto::failure;

using result = proto::result<stage>;

struct bridge: bridge_client {
    static
    void
    exit(_In_ result value)
    {
        (void)bridge_client::send(
            method_exit,
            value.packed_status(),
            value.native_code()
            );
    }

    static
    bool
    wait_for_download(
        _In_ uintptr_t attempt,
        _In_ uintptr_t native_error_code = 0
        )
    {
        return wait(method_download, attempt, native_error_code);
    }

    static
    bool
    wait_for_extract()
    {
        return wait(method_extract);
    }

    static
    bool
    wait_for_execute()
    {
        return wait(method_execute);
    }

    static
    bool
    wait_for_host()
    {
        return wait_for_download(0);
    }

private:
    static
    bool
    wait(
        _In_ uint16_t method,
        _In_ uintptr_t value1 = 0,
        _In_ uintptr_t value2 = 0,
        _In_ uintptr_t value3 = 0,
        _In_ uintptr_t value4 = 0
        )
    {
        for (;;)
        {
            const auto response = bridge_client::send(
                method,
                value1,
                value2,
                value3,
                value4
                );

            if (response && response->value1 == response_continue)
            {
                return true;
            }

            if (response && response->value1 == response_abort)
            {
                return false;
            }

            Sleep(bridge_wait_milliseconds);
        }
    }
};

//////////////////////////////////////////////////////////////////////////
// Parameters.
//////////////////////////////////////////////////////////////////////////

enum class parameter_error : uint8_t {
    flags                   = 0x01,
};

template <>
struct proto::is_error_code<parameter_error> : std::true_type {};

struct parameters {
    parameter_flags flags;
    int32_t show_window = SW_SHOWNORMAL;
    wchar_t* url;
    wchar_t* download_path;
    wchar_t* extraction_directory;
    wchar_t* executable_path;
    wchar_t* arguments;
    wchar_t* working_directory;
};

auto
parse_parameters(
    _In_ void* data
    ) -> std::expected<parameters, parameter_error>
{
    parameters parameters{};
    proto::reader reader(data);

    parameters.flags =
        static_cast<parameter_flags>(reader.next_uint32());

    if (has_any(parameters.flags, ~valid_flags)
        || (has_any(parameters.flags, execute_flags)
            && !has_all(parameters.flags, parameter_flags::execute))
        || (has_all(parameters.flags, parameter_flags::extract)
            && !has_all(parameters.flags, parameter_flags::download)))
    {
        return std::unexpected(parameter_error::flags);
    }

    if (has_any(parameters.flags, parameter_flags::download))
    {
        parameters.url = reader.next_wstring();

        parameters.download_path = reader.next_wstring();
    }

    if (has_any(parameters.flags, parameter_flags::extract))
    {
        parameters.extraction_directory = reader.next_wstring();
    }

    if (has_any(parameters.flags, parameter_flags::execute))
    {
        parameters.executable_path = reader.next_wstring();

        if (has_any(parameters.flags, parameter_flags::arguments))
        {
            parameters.arguments = reader.next_wstring();
        }

        if (has_any(
            parameters.flags,
            parameter_flags::working_directory
            ))
        {
            parameters.working_directory = reader.next_wstring();
        }

        if (has_any(parameters.flags, parameter_flags::show_window))
        {
            parameters.show_window = reader.next_int32();
        }
    }

    return parameters;
}

//////////////////////////////////////////////////////////////////////////
// ComPtr and Variant helpers.
//////////////////////////////////////////////////////////////////////////

template <typename T>
class ComPtr {
public:
    using InterfaceType = T;

    ComPtr() = default;
    ComPtr(_In_ const ComPtr&) = delete;
    ComPtr& operator=(_In_ const ComPtr&) = delete;

    ~ComPtr()
    {
        // It saves us few bytes to not call Reset() here.
        if (this->ptr_ != nullptr)
        {
            this->ptr_->Release();
        }
    }

    InterfaceType* Get() const { return this->ptr_; }
    InterfaceType* operator->() const { return this->ptr_; }
    operator InterfaceType*() const { return this->ptr_; }
    explicit operator bool() const { return this->ptr_ != nullptr; }

    // CComPtr::ReleaseAndGetAddressOf, but with a shorter name.
    InterfaceType** Put()
    {
        this->Reset();
        return &this->ptr_;
    }

    ULONG Reset()
    {
        InterfaceType* value = this->ptr_;

        if (value != nullptr)
        {
            this->ptr_ = nullptr;
            return value->Release();
        }

        return 0;
    }

protected:
    InterfaceType* ptr_ = nullptr;
};

class Variant : public VARIANT {
public:
    Variant() { VariantInit(this); }
    ~Variant() { VariantClear(this); }

    explicit Variant(_In_ LONG lValue) : Variant{}
    {
        this->vt = VT_I4;
        this->lVal = lValue;
    }

    explicit Variant(_In_opt_ LPCWSTR wszValue) : Variant{}
    {
        this->vt = VT_BSTR;
        this->bstrVal = SysAllocString(wszValue);
    }

    explicit Variant(_In_opt_ IDispatch* pDispatch) : Variant{}
    {
        this->vt = VT_DISPATCH;
        this->pdispVal = pDispatch;

        if (this->pdispVal != nullptr)
        {
            this->pdispVal->AddRef();
        }
    }

    Variant(_In_ const Variant&) = delete;
    Variant& operator=(_In_ const Variant&) = delete;
};

//////////////////////////////////////////////////////////////////////////
// Path helpers.
//////////////////////////////////////////////////////////////////////////

BOOLEAN
ExpandPath(
    _In_ LPCWSTR wszSource,
    _Out_writes_(cchDestination) LPWSTR wszDestination,
    _In_ DWORD cchDestination
    )
{
    DWORD size = ExpandEnvironmentStringsW(
        wszSource,
        wszDestination,
        cchDestination
        );

    if (size == 0 || size > cchDestination)
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
TruncateToParentDirectory(
    _Inout_z_ LPWSTR wszPath
    )
{
    LPWSTR separator = NULL;

    for (LPWSTR cursor = wszPath; *cursor != L'\0'; ++cursor)
    {
        if (*cursor == L'\\' || *cursor == L'/')
        {
            separator = cursor;
        }
    }

    if (separator == NULL)
    {
        return FALSE;
    }

    if (separator == wszPath
        || (separator == wszPath + sizeof(WCHAR) && wszPath[1] == L':'))
    {
        ++separator;
    }

    *separator = L'\0';
    return TRUE;
}

DWORD
EnsureDirectory(
    _In_ LPCWSTR wszPath
    )
{
    int status = SHCreateDirectoryExW(NULL, wszPath, NULL);

    if (status == ERROR_SUCCESS
        || status == ERROR_FILE_EXISTS
        || status == ERROR_ALREADY_EXISTS)
    {
        return ERROR_SUCCESS;
    }

    return static_cast<DWORD>(status);
}

DWORD
CreateParentDirectory(
    _In_ LPCWSTR wszPath
    )
{
    WCHAR wszDirectory[MAX_PATH];
    wcscpy(wszDirectory, wszPath);

    if (!TruncateToParentDirectory(wszDirectory))
    {
        return ERROR_SUCCESS;
    }

    return EnsureDirectory(wszDirectory);
}

//////////////////////////////////////////////////////////////////////////
// Download.
//////////////////////////////////////////////////////////////////////////

enum class download_error : uint8_t {
    create_directory        = 0x01,
    url_download            = 0x02,
};

template <>
struct proto::is_error_code<download_error> : std::true_type {};

auto
DownloadInternal(
    _In_ LPCWSTR wszUrl,
    _In_ LPCWSTR wszPath
    ) -> std::expected<void, failure<download_error>>
{
    uintptr_t attempt = 1;

    for (;; ++attempt)
    {
        HRESULT hr = URLDownloadToFileW(NULL, wszUrl, wszPath, 0, NULL);

        if (SUCCEEDED(hr))
        {
            return {};
        }

        if (!bridge::wait_for_download(attempt, static_cast<uintptr_t>(hr)))
        {
            return std::unexpected(
                failure{ download_error::url_download, hr }
                );
        }
    }
}

auto
Download(
    _In_ LPCWSTR wszUrl,
    _In_ LPCWSTR wszPath
    ) -> std::expected<void, failure<download_error>>
{
    DWORD error;

    //
    // Ensure the download path's parent directory exists.
    //

    error = CreateParentDirectory(wszPath);

    if (error != ERROR_SUCCESS)
    {
        return std::unexpected(
            failure{ download_error::create_directory, error }
            );
    }

    //
    // Download loop.
    //

    return DownloadInternal(wszUrl, wszPath);
}

//////////////////////////////////////////////////////////////////////////
// Extract.
//////////////////////////////////////////////////////////////////////////

enum class extract_error : uint8_t {
    create_directory        = 0x01,
    create_shell            = 0x02,
    open_archive            = 0x03,
    open_output             = 0x04,
    get_archive_items       = 0x05,
    count_archive_items     = 0x06,
    copy_items              = 0x07,
    get_output_items        = 0x08,
    count_output_items      = 0x09,
    timeout                 = 0x0a,
};

template <>
struct proto::is_error_code<extract_error> : std::true_type {};

auto
ExtractInternal(
    _In_ LPCWSTR wszArchivePath,
    _In_ LPCWSTR wszOutputPath
    ) -> std::expected<void, failure<extract_error>>
{
    //
    // Create Shell.Application object.
    //

    HRESULT hr;

    ComPtr<IShellDispatch> pShell;
    hr = CoCreateInstance(
        *_(&CLSID_Shell),
        NULL,
        CLSCTX_INPROC_SERVER,
        *_(&IID_IShellDispatch),
        reinterpret_cast<void**>(pShell.Put())
        );

    if (FAILED(hr) || !pShell)
    {
        return std::unexpected(
            failure{ extract_error::create_shell, hr }
            );
    }

    //
    // Get Folder object for the archive.
    //

    ComPtr<Folder> pArchiveFolder;
    hr = pShell->NameSpace(
        Variant{ wszArchivePath },
        pArchiveFolder.Put()
        );

    if (FAILED(hr) || !pArchiveFolder)
    {
        return std::unexpected(
            failure{ extract_error::open_archive, hr }
            );
    }

    //
    // Get Folder object for the output directory.
    //

    ComPtr<Folder> pOutputFolder;
    hr = pShell->NameSpace(
        Variant{ wszOutputPath },
        pOutputFolder.Put()
        );

    if (FAILED(hr) || !pOutputFolder)
    {
        return std::unexpected(
            failure{ extract_error::open_output, hr }
            );
    }

    //
    // Get the Items collection from the archive folder.
    //

    ComPtr<FolderItems> pArchiveItems;
    hr = pArchiveFolder->Items(pArchiveItems.Put());

    if (FAILED(hr) || !pArchiveItems)
    {
        return std::unexpected(
            failure{ extract_error::get_archive_items, hr }
            );
    }

    //
    // Count the archive items and copy them to the output folder.
    //

    LONG lArchiveItemCount = 0;
    hr = pArchiveItems->get_Count(&lArchiveItemCount);

    if (FAILED(hr))
    {
        return std::unexpected(
            failure{ extract_error::count_archive_items, hr }
            );
    }

    hr = pOutputFolder->CopyHere(
        Variant{ &*pArchiveItems },
        Variant{ extract_copy_options }
        );

    if (FAILED(hr))
    {
        return std::unexpected(
            failure{ extract_error::copy_items, hr }
            );
    }

    if (lArchiveItemCount == 0)
    {
        return {};
    }

    //
    // Wait for extraction to complete by polling the output folder
    // until it has the same number of items as the archive.
    //

    for (uint32_t attempt = 0; attempt < extraction_poll_limit; ++attempt)
    {
        Sleep(extraction_poll_milliseconds);

        ComPtr<FolderItems> pOutputItems;
        hr = pOutputFolder->Items(pOutputItems.Put());

        if (FAILED(hr) || !pOutputItems)
        {
            return std::unexpected(
                failure{ extract_error::get_output_items, hr }
                );
        }

        LONG lOutputItemCount = 0;
        hr = pOutputItems->get_Count(&lOutputItemCount);

        if (FAILED(hr))
        {
            return std::unexpected(
                failure{ extract_error::count_output_items, hr }
                );
        }

        if (lOutputItemCount >= lArchiveItemCount)
        {
            return {};
        }
    }

    return std::unexpected(
        failure{ extract_error::timeout, ERROR_TIMEOUT }
        );
}

auto
Extract(
    _In_ LPCWSTR wszArchivePath,
    _In_ LPCWSTR wszOutputPath
    ) -> std::expected<void, failure<extract_error>>
{
    DWORD error;

    //
    // Ensure the output directory exists.
    //

    error = EnsureDirectory(wszOutputPath);

    if (error != ERROR_SUCCESS)
    {
        return std::unexpected(
            failure{ extract_error::create_directory, error }
            );
    }

    //
    // Extract the archive into the output directory.
    //

    return ExtractInternal(wszArchivePath, wszOutputPath);
}

//////////////////////////////////////////////////////////////////////////
// Execute.
//////////////////////////////////////////////////////////////////////////

enum class execute_error : uint8_t {
    shell_execute           = 0x01,
};

template <>
struct proto::is_error_code<execute_error> : std::true_type {};

auto
Execute(
    _In_ LPCWSTR wszExecutablePath,
    _In_opt_ LPCWSTR wszArguments,
    _In_opt_ LPCWSTR wszWorkingDirectory,
    _In_ INT nShow
    ) -> std::expected<void, failure<execute_error>>
{
    SHELLEXECUTEINFOW sei{
        .cbSize = sizeof(SHELLEXECUTEINFOW),
        .lpFile = wszExecutablePath,
        .lpParameters = wszArguments,
        .lpDirectory = wszWorkingDirectory,
        .nShow = nShow,
    };

    if (!ShellExecuteExW(&sei))
    {
        return std::unexpected(
            failure{ execute_error::shell_execute }
            );
    }

    return {};
}

//////////////////////////////////////////////////////////////////////////
// Main.
//////////////////////////////////////////////////////////////////////////

auto
Entry(
    _In_opt_ LPCWSTR wszUrl,
    _In_opt_ LPCWSTR wszDownloadPath,
    _In_opt_ LPCWSTR wszExtractionPath,
    _In_opt_ LPCWSTR wszExecutablePath,
    _In_opt_ LPCWSTR wszArguments,
    _In_opt_ LPCWSTR wszWorkingDirectory,
    _In_ INT nShow
    ) -> result
{
    //
    // Download stage.
    //

    if (wszDownloadPath != NULL)
    {
        if (const auto download = Download(wszUrl, wszDownloadPath); !download)
        {
            return result::operation_failed(
                stage::download,
                download.error()
                );
        }
    }

    if (wszExtractionPath != NULL)
    {
        if (!bridge::wait_for_extract())
        {
            return result::aborted(stage::extract);
        }

        //
        // Extract the downloaded archive.
        //

        if (const auto extraction = Extract(
            wszDownloadPath,
            wszExtractionPath
            ); !extraction)
        {
            return result::operation_failed(
                stage::extract,
                extraction.error()
                );
        }
    }

    if (wszExecutablePath != NULL)
    {
        if (!bridge::wait_for_execute())
        {
            return result::aborted(stage::execute);
        }

        if (const auto execution = Execute(
            wszExecutablePath,
            wszArguments,
            wszWorkingDirectory,
            nShow
            ); !execution)
        {
            return result::operation_failed(
                stage::execute,
                execution.error()
                );
        }

        return result::success(stage::execute);
    }

    if (wszExtractionPath != NULL)
    {
        return result::success(stage::extract);
    }

    if (wszDownloadPath != NULL)
    {
        return result::success(stage::download);
    }

    return result::success(stage::none);
}

enum class initialization_error : uint8_t {
    initialize_com          = 0x01,
    expand_download_path    = 0x02,
    expand_extraction_path  = 0x03,
    expand_executable_path  = 0x04,
    expand_working_directory = 0x05,
};

template <>
struct proto::is_error_code<initialization_error> : std::true_type {};

result
__fastcall
__entry(
    _In_ const parameters& parameters
    )
{
    //
    // Expand DownloadPath.
    //

    WCHAR wszDownloadPath[MAX_PATH];
    LPCWSTR pwszDownloadPath = NULL;

    if (has_any(parameters.flags, parameter_flags::download))
    {
        if (!ExpandPath(parameters.download_path, wszDownloadPath, MAX_PATH))
        {
            return result::operation_failed(
                stage::initialization,
                failure{ initialization_error::expand_download_path }
                );
        }

        pwszDownloadPath = wszDownloadPath;
    }

    //
    // Expand ExtractionDirectory.
    //

    WCHAR wszExtractionPath[MAX_PATH];
    LPCWSTR pwszExtractionPath = NULL;

    if (has_any(parameters.flags, parameter_flags::extract))
    {
        if (!ExpandPath(
            parameters.extraction_directory,
            wszExtractionPath,
            MAX_PATH
            ))
        {
            return result::operation_failed(
                stage::initialization,
                failure{ initialization_error::expand_extraction_path }
                );
        }

        pwszExtractionPath = wszExtractionPath;
    }

    //
    // Prepare execution paths.
    //

    WCHAR wszExecutablePath[MAX_PATH];
    LPCWSTR pwszExecutablePath = NULL;
    WCHAR wszWorkingDirectory[MAX_PATH];
    LPCWSTR pwszWorkingDirectory = NULL;

    if (has_any(parameters.flags, parameter_flags::execute))
    {
        //
        // Expand ExecutablePath.
        //

        if (!ExpandPath(
            parameters.executable_path,
            wszExecutablePath,
            MAX_PATH
            ))
        {
            return result::operation_failed(
                stage::initialization,
                failure{ initialization_error::expand_executable_path }
                );
        }

        pwszExecutablePath = wszExecutablePath;

        //
        // Expand WorkingDirectory, or default to dirname(ExecutablePath).
        //

        if (parameters.working_directory != NULL)
        {
            if (!ExpandPath(
                parameters.working_directory,
                wszWorkingDirectory,
                MAX_PATH
                ))
            {
                return result::operation_failed(
                    stage::initialization,
                    failure{ initialization_error::expand_working_directory }
                    );
            }

            pwszWorkingDirectory = wszWorkingDirectory;
        }
        else
        {
            wcscpy(wszWorkingDirectory, wszExecutablePath);

            if (TruncateToParentDirectory(wszWorkingDirectory))
            {
                pwszWorkingDirectory = wszWorkingDirectory;
            }
        }
    }

    //
    // Initialize COM for Shell operations.
    //

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (FAILED(hr))
    {
        return result::operation_failed(
            stage::initialization,
            failure{ initialization_error::initialize_com, hr }
            );
    }

    //
    // Run the requested stages.
    //

    auto result = Entry(
        parameters.url,
        pwszDownloadPath,
        pwszExtractionPath,
        pwszExecutablePath,
        parameters.arguments,
        pwszWorkingDirectory,
        parameters.show_window
        );

    //
    // Uninitialize COM.
    //

    CoUninitialize();

    return result;
}

result
__fastcall
_entry(
    _In_ void* data
    )
{
    if (!bridge::wait_for_host())
    {
        return result::aborted(stage::download);
    }

    if (const auto parameters = parse_parameters(data); parameters)
    {
        return __entry(*parameters);
    }
    else
    {
        return result::invalid_parameters(
            stage::parameters,
            failure{ parameters.error(), 0 }
            );
    }
}

extern "C"
void
__fastcall
entry(
    _In_ void* argument1,
    _In_opt_ void* argument2
    )
{
    (void)argument2;

    bridge::exit(_entry(argument1));
}

} // namespace sc
