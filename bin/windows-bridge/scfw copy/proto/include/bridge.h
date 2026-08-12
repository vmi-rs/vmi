#pragma once

#include <cstdint>
#include <optional>

namespace sc {
namespace proto {
namespace bridge {

//
// The transports map this common packet layout to their register ABIs.
//
//                                       CPUID   |   VMCALL
//                                     x64 | x86 | x64 | x86
struct packet {                     // ----|-----|-----|----
    uint32_t magic;                 // eax | eax | ecx | ebp
    uint16_t request;               // ecx | ecx | edx | edx (lower 16 bits)
    uint16_t method;                // ecx | ecx | edx | edx (upper 16 bits)
    uintptr_t value1;               // r8  | ebx | r8  | esi
    uintptr_t value2;               // r9  | edx | r9  | edi
    uintptr_t value3;               // r10 | esi | r10 | -
    uintptr_t value4;               // r11 | edi | r11 | -
};

//                                       CPUID   |   VMCALL
//                                     x64 | x86 | x64 | x86
struct response {                   // ----|-----|-----|----
    uintptr_t value1;               // rax | eax | rax | eax
    uintptr_t value2;               // rbx | ebx | rbx | ebx
    uintptr_t value3;               // rcx | ecx | rcx | ecx
    uintptr_t value4;               // rdx | edx | rdx | edx
};

using transport_fn = uintptr_t(__fastcall*)(
    _In_ const packet*,
    _Out_opt_ response*
    );

extern "C"
uintptr_t
__fastcall
bridge_cpuid(
    _In_ const packet* packet,
    _Out_opt_ response* response
    );

extern "C"
uintptr_t
__fastcall
bridge_xen_vmcall(
    _In_ const packet* packet,
    _Out_opt_ response* response
    );

template <
    transport_fn Send,
    uint32_t Magic,
    uint16_t Request,
    uintptr_t VerifyValue3,
    uintptr_t VerifyValue4
>
struct client {
    //
    // Returns no response when the host does not stamp both verification values.
    //
    static
    std::optional<response>
    send(
        uint16_t method,
        uintptr_t value1 = 0,
        uintptr_t value2 = 0,
        uintptr_t value3 = 0,
        uintptr_t value4 = 0
        )
    {
        const packet packet{
            .magic = Magic,
            .request = Request,
            .method = method,
            .value1 = value1,
            .value2 = value2,
            .value3 = value3,
            .value4 = value4,
        };

        response response{};
        Send(&packet, &response);

        if (response.value3 != VerifyValue3 || response.value4 != VerifyValue4)
        {
            return std::nullopt;
        }

        return response;
    }
};

} // namespace bridge
} // namespace proto
} // namespace sc
