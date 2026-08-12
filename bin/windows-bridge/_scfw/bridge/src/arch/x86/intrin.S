    .intel_syntax noprefix

#
# BridgePacket field offsets (x86).
#

#define BRIDGE_PACKET_MAGIC     0
#define BRIDGE_PACKET_REQUEST   4
#define BRIDGE_PACKET_METHOD    6
#define BRIDGE_PACKET_VALUE1    8
#define BRIDGE_PACKET_VALUE2    12
#define BRIDGE_PACKET_VALUE3    16
#define BRIDGE_PACKET_VALUE4    20

#
# BridgeResponse field offsets (x86).
#

#define BRIDGE_RESPONSE_VALUE1  0
#define BRIDGE_RESPONSE_VALUE2  4
#define BRIDGE_RESPONSE_VALUE3  8
#define BRIDGE_RESPONSE_VALUE4  12

    .section .text$15,"ax"

#++
#
# uintptr_t
# __fastcall
# __bridge_cpuid (
#    _In_ const bridge_packet_t* packet,
#    _Out_opt_ bridge_response_t* response
#    )
#
# Routine Description:
#
#    This function is an extended version of the __cpuid intrinsic.
#    It allows the caller to specify values of the EAX, ECX, EBX, EDX,
#    ESI, and EDI registers.
#
#    The optional response structure will be filled with the results
#    of the CPUID instruction: EAX, EBX, ECX, and EDX.
#
# Arguments:
#
#    packet - Supplies the address of the bridge packet.
#    response - Supplies the address of the bridge response.
#
# Return Value:
#
#    Result of the CPUID instruction (EAX).
#
#--

    .globl @__bridge_cpuid@8
@__bridge_cpuid@8:

#
# EBX, ESI and EDI are non-volatile registers.
# EBX will be overwritten by the CPUID instruction and ESI/EDI hold
# the packet values.
# EDX is saved to hold the response structure address.
#

    push    ebx
    push    esi
    push    edi
    push    edx

#
# Assign the packet values to the registers.
#

    mov     ebx, dword ptr [ecx + BRIDGE_PACKET_VALUE1]
    mov     edx, dword ptr [ecx + BRIDGE_PACKET_VALUE2]
    mov     esi, dword ptr [ecx + BRIDGE_PACKET_VALUE3]
    mov     edi, dword ptr [ecx + BRIDGE_PACKET_VALUE4]
    mov     eax, dword ptr [ecx + BRIDGE_PACKET_MAGIC]
    mov     ecx, dword ptr [ecx + BRIDGE_PACKET_REQUEST]

#
# Execute the CPUID instruction.
#

    cpuid

#
# Restore the response structure address (previously held by EDX)
# to the EDI register.
#

    pop     edi
    test    edi, edi
    jz      1f

#
# Assign the CPUID results to the response structure.
#

    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE1], eax
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE2], ebx
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE3], ecx
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE4], edx

1:

#
# Finally, restore the non-volatile registers and return.
#

    pop     edi
    pop     esi
    pop     ebx

    ret

#++
#
# uintptr_t
# __fastcall
# __bridge_vmcall_xen (
#    _In_ const bridge_packet_t* packet,
#    _Out_opt_ bridge_response_t* response
#    )
#
# Routine Description:
#
#    This function performs a Xen VMCALL hypercall with the bridge
#    packet values in EBP, EDX, ESI, and EDI registers.
#
#    The optional response structure will be filled with the results
#    of the VMCALL instruction: EAX, EBX, ECX, and EDX.
#
# Arguments:
#
#    packet - Supplies the address of the bridge packet.
#    response - Supplies the address of the bridge response.
#
# Return Value:
#
#    Result of the VMCALL instruction (EAX).
#
#--

    .globl @__bridge_vmcall_xen@8
@__bridge_vmcall_xen@8:

#
# EBX will be overwritten by the VMCALL instruction and EDX holds
# the address of the response structure.
#

    push    ebp
    push    ebx
    push    esi
    push    edi
    push    edx

#
# Assign the packet values to the registers.
#

    mov     esi, dword ptr [ecx + BRIDGE_PACKET_VALUE1]
    mov     edi, dword ptr [ecx + BRIDGE_PACKET_VALUE2]
#   mov     ???, dword ptr [ecx + BRIDGE_PACKET_VALUE3]
#   mov     ???, dword ptr [ecx + BRIDGE_PACKET_VALUE4]
    mov     ebp, dword ptr [ecx + BRIDGE_PACKET_MAGIC]
    mov     edx, dword ptr [ecx + BRIDGE_PACKET_REQUEST]

#
# Execute the VMCALL instruction.
# Conform to the Xen VMCALL ABI.
#

    mov     eax, 0x22                   # __HYPERVISOR_hvm_op
    mov     ebx, 0x18                   # HVMOP_guest_request_vm_event
    xor     ecx, ecx                    # arg = NULL
    vmcall

#
# Restore the response structure address (previously held by EDX)
# to the EDI register.
#

    pop     edi
    test    edi, edi
    jz      1f

#
# Assign the VMCALL results to the response structure.
#

    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE1], eax
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE2], ebx
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE3], ecx
    mov     dword ptr [edi + BRIDGE_RESPONSE_VALUE4], edx

1:

#
# Finally, restore the non-volatile registers and return.
#

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp

    ret
