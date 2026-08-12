#pragma once
#include <optional>
#include <cstdint>

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

struct bridge_packet_cpuid_t        // x64 | x86
{                                   // ----+----
    uint32_t magic;                 // eax | eax
    uint16_t request;               // ecx | ecx (lower 16 bits)
    uint16_t method;                // ecx | ecx (upper 16 bits)
    uintptr_t value1;               // r8  | ebx
    uintptr_t value2;               // r9  | edx
    uintptr_t value3;               // r10 | esi
    uintptr_t value4;               // r11 | edi
};

struct bridge_packet_vmcall_xen_t   // x64 | x86
{                                   // ----+----
    uint32_t magic;                 // ecx | ebp
    uint16_t request;               // edx | edx (lower 16 bits)
    uint16_t method;                // edx | edx (upper 16 bits)
    uintptr_t value1;               // r8  | esi
    uintptr_t value2;               // r9  | edi
    uintptr_t value3;               // r10 |
    uintptr_t value4;               // r11 |
};

struct bridge_response_t            // x64 | x86
{                                   // ----+----
    uintptr_t value1;               // rax | eax
    uintptr_t value2;               // rbx | ebx
    uintptr_t value3;               // rcx | ecx
    uintptr_t value4;               // rdx | edx
};

#define bridge_packet_t     bridge_packet_vmcall_xen_t
#define __bridge_call       __bridge_vmcall_xen
//#define bridge_packet_t     bridge_packet_cpuid_t
//#define __bridge_call       __bridge_cpuid

extern "C"
uintptr_t
__fastcall
__bridge_cpuid(
    _In_ const bridge_packet_t* packet,
    _Out_opt_ bridge_response_t* response
    );

extern "C"
uintptr_t
__fastcall
__bridge_vmcall_xen(
    _In_ const bridge_packet_t* packet,
    _Out_opt_ bridge_response_t* response
    );

namespace sc
{

template <
    uint32_t MAGIC,
    uint16_t REQUEST,
    uint32_t...
>
struct bridge_base;

template <
    uint32_t MAGIC,
    uint16_t REQUEST
>
struct bridge_base<MAGIC, REQUEST>
{
    static
    uintptr_t
    request(
        _In_ uint16_t method,
        _In_ uintptr_t argument1 = 0,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        const bridge_packet_t packet = {
            MAGIC,
            REQUEST,
            method,
            argument1,
            argument2,
            argument3,
            argument4
        };

        return __bridge_call(&packet, nullptr);
    }

    static
    void
    error(
        _In_ uintptr_t error_code,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        request(0xFFFE, error_code, argument2, argument3, argument4);
    }

    static
    void
    exit(
        _In_ uintptr_t exit_code,
        _In_ uintptr_t argument2 = 0
        )
    {
        request(0xFFFF, exit_code, argument2);
    }
};

template <
    uint32_t MAGIC,
    uint16_t REQUEST,
    uint32_t VERIFY_VALUE4
>
struct bridge_base<MAGIC, REQUEST, VERIFY_VALUE4>
{
    static
    std::optional<uintptr_t>
    request(
        _In_ uint16_t method,
        _In_ uintptr_t argument1 = 0,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        const bridge_packet_t packet = {
            MAGIC,
            REQUEST,
            method,
            argument1,
            argument2,
            argument3,
            argument4
        };

        bridge_response_t response;
        uintptr_t result = __bridge_call(&packet, &response);

        if (response.value4 != VERIFY_VALUE4)
        {
            return std::nullopt;
        }

        return result;
    }

    static
    void
    error(
        _In_ uintptr_t error_code,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        request(0xFFFE, error_code, argument2, argument3, argument4);
    }

    static
    void
    exit(
        _In_ uintptr_t exit_code,
        _In_ uintptr_t argument2 = 0
        )
    {
        request(0xFFFF, exit_code, argument2);
    }
};

template <
    uint32_t MAGIC,
    uint16_t REQUEST,
    uint32_t VERIFY_VALUE4,
    uint32_t VERIFY_VALUE3
>
struct bridge_base<MAGIC, REQUEST, VERIFY_VALUE4, VERIFY_VALUE3>
{
    static
    std::optional<uintptr_t>
    request(
        _In_ uint16_t method,
        _In_ uintptr_t argument1 = 0,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        const bridge_packet_t packet = {
            MAGIC,
            REQUEST,
            method,
            argument1,
            argument2,
            argument3,
            argument4
        };

        bridge_response_t response;
        uintptr_t result = __bridge_call(&packet, &response);

        if (response.value4 != VERIFY_VALUE4 || response.value3 != VERIFY_VALUE3)
        {
            return std::nullopt;
        }

        return result;
    }

    static
    void
    error(
        _In_ uintptr_t error_code,
        _In_ uintptr_t argument2 = 0,
        _In_ uintptr_t argument3 = 0,
        _In_ uintptr_t argument4 = 0
        )
    {
        request(0xFFFE, error_code, argument2, argument3, argument4);
    }

    static
    void
    exit(
        _In_ uintptr_t exit_code,
        _In_ uintptr_t argument2 = 0
        )
    {
        request(0xFFFF, exit_code, argument2);
    }
};

}

///////////////////////////////////////////////////////////////////////////////

static constexpr uint32_t  BRIDGE_MAGIC         = 0x706e7964; // '@nyd'
static constexpr uintptr_t BRIDGE_VERIFY_VALUE4 = 0x616e7964; // 'anyd'
static constexpr uintptr_t BRIDGE_VERIFY_VALUE3 = 0x616e7964; // 'anyd'

static constexpr uint16_t  BRIDGE_REQUEST_DOWNLOAD                  = 0x0001;
static constexpr uint16_t  BRIDGE_REQUEST_FETCH_PROCESS_ENVIRONMENT = 0x8001;
static constexpr uint16_t  BRIDGE_REQUEST_TRANSFER_FILE_BY_HANDLE   = 0x8002;


template <uint16_t REQUEST>
using common_bridge = sc::bridge_base<
    BRIDGE_MAGIC,
    REQUEST,
    BRIDGE_VERIFY_VALUE4,
    BRIDGE_VERIFY_VALUE3
>;

///////////////////////////////////////////////////////////////////////////////

ULONG
NTAPI
ScNextParameterULONG (
    _Inout_ PVOID* Cursor
    )
{
    PULONG Parameter = (PULONG)*Cursor;

    *Cursor = (PVOID)((ULONG_PTR)Parameter + sizeof(ULONG));

    return *Parameter;
}

LPSTR
NTAPI
ScNextParameterA (
    _Inout_ PVOID* Cursor
    )
{
    LPSTR Parameter = (LPSTR)*Cursor;

    if (!*Parameter) {
        return nullptr;
    }

    *Cursor = (PVOID)((ULONG_PTR)Parameter + strlen((PCHAR)Parameter) + 1);

    return Parameter;
}

LPWSTR
NTAPI
ScNextParameterW (
    _Inout_ PVOID* Cursor
    )
{
    LPWSTR Parameter = (LPWSTR)*Cursor;

    if (!*Parameter) {
        return nullptr;
    }

    *Cursor = (PVOID)((ULONG_PTR)Parameter + (wcslen(Parameter) + 1) * sizeof(WCHAR));

    return Parameter;
}
