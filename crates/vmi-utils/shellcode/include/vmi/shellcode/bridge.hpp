#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>

namespace sc {
namespace vmi {

//
// x64 register mappings and proposed x86 packing (not implemented).
// Pairs are high:low, e.g. edx:ebx = (uint64_t(edx) << 32) | ebx.
// "-" means no register slot is available.
//
//                                         CPUID     |     VMCALL
//                                     x64 | x86     | x64 | x86
struct bridge_packet {              // ----|---------|-----|--------
    uint32_t magic;                 // eax | eax     | ecx | ebp
    uint16_t request;               // ecx | ecx     | edx | edx (lower 16 bits)
    uint16_t method;                // ecx | ecx     | edx | edx (upper 16 bits)
    uint64_t value1;                // r8  | edx:ebx | r8  | edi:esi
    uint64_t value2;                // r9  | edi:esi | r9  | -
    uint64_t value3;                // r10 | -       | r10 | -
    uint64_t value4;                // r11 | -       | r11 | -
};

//                                         CPUID     |     VMCALL
//                                     x64 | x86     | x64 | x86
struct bridge_response {            // ----|---------|-----|--------
    uint64_t value1;                // rax | edx:eax | rax | edx:eax
    uint64_t value2;                // rbx | ecx:ebx | rbx | ecx:ebx
    uint64_t value3;                // rcx | -       | rcx | -
    uint64_t value4;                // rdx | -       | rdx | -
};

using bridge_transport = uint64_t(__fastcall*)(
    _In_ const bridge_packet*,
    _Out_opt_ bridge_response*
    );

extern "C"
uint64_t
__fastcall
bridge_cpuid(
    _In_ const bridge_packet* packet,
    _Out_opt_ bridge_response* response
    );

extern "C"
uint64_t
__fastcall
bridge_xen_vmcall(
    _In_ const bridge_packet* packet,
    _Out_opt_ bridge_response* response
    );

struct default_bridge_traits {
    static constexpr bridge_transport transport = &bridge_xen_vmcall;
    static constexpr uint32_t magic = 0x42494d56;                 // "VMIB"
    static constexpr uint64_t verify_value3 = 0x213353522d494d56; // "VMI-RS3!"
    static constexpr uint64_t verify_value4 = 0x213453522d494d56; // "VMI-RS4!"
};

template <typename Traits>
concept bridge_traits = requires {
    typename std::integral_constant<bridge_transport, Traits::transport>;
    typename std::integral_constant<uint32_t, Traits::magic>;
    typename std::integral_constant<uint16_t, Traits::request>;
    typename std::integral_constant<uint64_t, Traits::verify_value3>;
    typename std::integral_constant<uint64_t, Traits::verify_value4>;
};

template <bridge_traits Traits>
struct bridge {
    //
    // Sends a bridge request and verifies the response before returning it.
    // Returns `std::nullopt` if the verification fails.
    //

    static
    std::optional<bridge_response>
    send(
        uint16_t method,
        uint64_t value1 = 0,
        uint64_t value2 = 0,
        uint64_t value3 = 0,
        uint64_t value4 = 0
        )
    {
        const bridge_packet packet{
            .magic = Traits::magic,
            .request = Traits::request,
            .method = method,
            .value1 = value1,
            .value2 = value2,
            .value3 = value3,
            .value4 = value4,
        };

        bridge_response response{};
        Traits::transport(&packet, &response);

        if (response.value3 != Traits::verify_value3
            || response.value4 != Traits::verify_value4)
        {
            return std::nullopt;
        }

        return response;
    }
};

} // namespace vmi
} // namespace sc
