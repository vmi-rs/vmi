#pragma once

#include <cstdint>
#include <optional>
#include <type_traits>

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

struct default_client_traits {
    static constexpr transport_fn transport = &bridge_xen_vmcall;
    static constexpr uint32_t magic = 0x42494d56;                  // "VMIB"
    static constexpr uintptr_t verify_value3 = 0x213353522d494d56; // "VMI-RS3!"
    static constexpr uintptr_t verify_value4 = 0x213453522d494d56; // "VMI-RS4!"
};

template <typename Traits>
concept client_traits = requires {
    typename std::integral_constant<transport_fn, Traits::transport>;
    typename std::integral_constant<uint32_t, Traits::magic>;
    typename std::integral_constant<uint16_t, Traits::request>;
    typename std::integral_constant<uintptr_t, Traits::verify_value3>;
    typename std::integral_constant<uintptr_t, Traits::verify_value4>;
};

template <client_traits Traits>
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
            .magic = Traits::magic,
            .request = Traits::request,
            .method = method,
            .value1 = value1,
            .value2 = value2,
            .value3 = value3,
            .value4 = value4,
        };

        response response{};
        Traits::transport(&packet, &response);

        if (response.value3 != Traits::verify_value3
            || response.value4 != Traits::verify_value4)
        {
            return std::nullopt;
        }

        return response;
    }
};

} // namespace bridge
} // namespace proto
} // namespace sc
