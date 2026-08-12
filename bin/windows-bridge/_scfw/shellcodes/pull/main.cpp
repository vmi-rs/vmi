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
IMPORT_END();

namespace sc {

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
    (void)argument1;
    (void)argument2;
}

} // namespace sc
