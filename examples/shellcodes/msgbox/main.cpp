// User-mode shellcode to display a message box with a specified title and text.
//
// The parameter buffer contains two NUL-terminated byte strings, for example:
//     "Title\0Message\0"

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

#include <vmi/shellcode.hpp>

#include <cstdint>
#include <windows.h>

IMPORT_BEGIN();
    IMPORT_MODULE("user32.dll");
        IMPORT_SYMBOL(MessageBoxA);
IMPORT_END();

namespace sc {

struct bridge_traits : vmi::default_bridge_traits {
    //
    // The request code used by the bridge to identify this shellcode.
    //
    // This value is arbitrary but must match the request code expected
    // by the receiving side.
    //
    // See `MsgBoxBridge::REQUEST` in
    //     examples/windows-shellcode/msgbox/bridge.rs
    //

    static constexpr uint16_t request = 0x0001;
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
        _In_ int result
        )
    {
        (void)send(
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
    (void)argument2; // Unused parameter.

    vmi::cursor parameters{ argument1 };
    const auto title = parameters.next_string();
    const auto text = parameters.next_string();
    const auto result = MessageBoxA(
        NULL,
        text,
        title,
        MB_OK | MB_SETFOREGROUND | MB_TOPMOST
        );

    bridge::exit(result);
}

} // namespace sc
