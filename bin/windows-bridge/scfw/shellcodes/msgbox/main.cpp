// The parameter buffer contains two consecutive NUL-terminated byte strings:
// the window title followed by the message text. The bytes are passed unchanged
// to MessageBoxA and must use the target process's active ANSI code page.

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
#include "reader.h"

#include <cstdint>
#include <windows.h>

IMPORT_BEGIN();
    IMPORT_MODULE("user32.dll");
        IMPORT_SYMBOL(MessageBoxA);
IMPORT_END();

namespace sc {

constexpr uint32_t bridge_magic = 0x42494d56;                 // "VMIB"
constexpr uint16_t msgbox_request = 0x0002;
constexpr uintptr_t bridge_verify_value3 = 0x213353522d494d56; // "VMI-RS3!"
constexpr uintptr_t bridge_verify_value4 = 0x213453522d494d56; // "VMI-RS4!"
constexpr uint16_t method_exit = 0xffff;

using bridge_client = proto::bridge::client<
    &proto::bridge::bridge_xen_vmcall,
    bridge_magic,
    msgbox_request,
    bridge_verify_value3,
    bridge_verify_value4
    >;

struct bridge: bridge_client {
    static
    void
    exit(
        _In_ int result
        )
    {
        (void)bridge_client::send(
            method_exit,
            static_cast<uintptr_t>(result)
            );
    }
};

extern "C"
void
__fastcall
entry(
    _In_ void* argument1,
    _In_opt_ void* argument2
    )
{
    (void)argument2;

    proto::reader parameters{ argument1 };
    const auto title = parameters.next_string();
    const auto text = parameters.next_string();
    const auto result = MessageBoxA(NULL, text, title, MB_OK);

    bridge::exit(result);
}

} // namespace sc
