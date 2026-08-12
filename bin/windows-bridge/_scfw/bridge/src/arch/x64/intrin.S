    .intel_syntax noprefix

#
# BridgePacket field offsets (x64).
#

#define BRIDGE_PACKET_MAGIC     0
#define BRIDGE_PACKET_REQUEST   4
#define BRIDGE_PACKET_METHOD    6
#define BRIDGE_PACKET_VALUE1    8
#define BRIDGE_PACKET_VALUE2    16
#define BRIDGE_PACKET_VALUE3    24
#define BRIDGE_PACKET_VALUE4    32

#
# BridgeResponse field offsets (x64).
#

#define BRIDGE_RESPONSE_VALUE1  0
#define BRIDGE_RESPONSE_VALUE2  8
#define BRIDGE_RESPONSE_VALUE3  16
#define BRIDGE_RESPONSE_VALUE4  24

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
#    It allows the caller to specify values of the EAX, ECX, R8, R9,
#    R10, and R11 registers.
#
#    The optional response structure will be filled with the results
#    of the CPUID instruction: RAX, RBX, RCX, and RDX.
#
# Arguments:
#
#    packet - Supplies the address of the bridge packet.
#    response - Supplies the address of the bridge response.
#
# Return Value:
#
#    Result of the CPUID instruction (RAX).
#
#--

    .globl __bridge_cpuid
__bridge_cpuid:

#
# Both RBX and RDX will be overwritten by the CPUID instruction.
# RBX is non-volatile register and RDX holds the address
# of the response structure.
#

    push    rbx
    push    rdx

#
# Assign the packet values to the registers.
#

    mov     r8,  qword ptr [rcx + BRIDGE_PACKET_VALUE1]
    mov     r9,  qword ptr [rcx + BRIDGE_PACKET_VALUE2]
    mov     r10, qword ptr [rcx + BRIDGE_PACKET_VALUE3]
    mov     r11, qword ptr [rcx + BRIDGE_PACKET_VALUE4]
    mov     eax, dword ptr [rcx + BRIDGE_PACKET_MAGIC]
    mov     ecx, dword ptr [rcx + BRIDGE_PACKET_REQUEST]

#
# Execute the CPUID instruction.
#

    cpuid

#
# Restore the response structure address (previously held by RDX)
# to the R8 register.
#

    pop     r8
    test    r8, r8
    jz      1f

#
# Assign the CPUID results to the response structure.
#

    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE1], rax
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE2], rbx
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE3], rcx
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE4], rdx

1:

#
# Finally, restore the non-volatile registers and return.
#

    pop     rbx
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
#    packet values in ECX, EDX, R8, R9, R10, and R11 registers.
#
#    The optional response structure will be filled with the results
#    of the VMCALL instruction: RAX, RBX, RCX, and RDX.
#
# Arguments:
#
#    packet - Supplies the address of the bridge packet.
#    response - Supplies the address of the bridge response.
#
# Return Value:
#
#    Result of the VMCALL instruction (RAX).
#
#--

    .globl __bridge_vmcall_xen
__bridge_vmcall_xen:

#
# Both RBX and RDX will be overwritten by the VMCALL instruction.
# RBX is non-volatile register and RDX holds the address
# of the response structure.
#

    push    rbx
    push    rsi
    push    rdi
    push    rdx

#
# Assign the packet values to the registers.
#

    mov     r8,  qword ptr [rcx + BRIDGE_PACKET_VALUE1]
    mov     r9,  qword ptr [rcx + BRIDGE_PACKET_VALUE2]
    mov     r10, qword ptr [rcx + BRIDGE_PACKET_VALUE3]
    mov     r11, qword ptr [rcx + BRIDGE_PACKET_VALUE4]
    mov     edx, dword ptr [rcx + BRIDGE_PACKET_REQUEST]
    mov     ecx, dword ptr [rcx + BRIDGE_PACKET_MAGIC]

#
# Execute the VMCALL instruction.
# Conform to the Xen VMCALL ABI.
#

    mov     eax, 0x22                   # __HYPERVISOR_hvm_op
    mov     edi, 0x18                   # HVMOP_guest_request_vm_event
    xor     rsi, rsi                    # arg = NULL
    vmcall

#
# Restore the response structure address (previously held by RDX)
# to the R8 register.
#

    pop     r8
    test    r8, r8
    jz      1f

#
# Assign the VMCALL results to the response structure.
#

    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE1], rax
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE2], rbx
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE3], rcx
    mov     qword ptr [r8 + BRIDGE_RESPONSE_VALUE4], rdx

1:

#
# Finally, restore the non-volatile registers and return.
#

    pop     rdi
    pop     rsi
    pop     rbx
    ret
