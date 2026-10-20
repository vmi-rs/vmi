//
// bridge_packet field offsets.
//

#define BRIDGE_PACKET_MAGIC     0
#define BRIDGE_PACKET_REQUEST   4
#define BRIDGE_PACKET_VALUE1    8
#define BRIDGE_PACKET_VALUE3    24

//
// bridge_response field offsets.
//

#define BRIDGE_RESPONSE_VALUE1  0
#define BRIDGE_RESPONSE_VALUE3  16

//
// Comment of the BRK instruction that makes a bridge call. vmi-utils names
// it bridge::BREAKPOINT_COMMENT.
//

#define BRIDGE_BREAKPOINT_COMMENT 0x4d56

//
// Mach-O prefixes the names of C symbols with an underscore.
//

#if defined(__APPLE__)
#define BRIDGE_SYMBOL(Name) _##Name
#else
#define BRIDGE_SYMBOL(Name) Name
#endif

    .text
    .p2align 2

//++
//
// uint64_t
// bridge_brk (
//    const bridge_packet* packet,
//    bridge_response* response
//    )
//
// Routine Description:
//
//    This function makes a bridge call with a BRK instruction. It passes
//    the magic in W0, the request and the method in W1, and the values in
//    X2 to X5.
//
//    The function fills the optional response structure with X0 to X3 as
//    the host leaves them after the BRK instruction.
//
//    Without a host, the BRK instruction raises a breakpoint exception in
//    the guest. A user-mode caller handles the resulting signal, such as
//    SIGTRAP on macOS. Its handler sets X0 to X3 to zero and resumes after
//    the BRK instruction, so the response fails verification.
//
// Arguments:
//
//    packet - Supplies the address of the bridge packet.
//    response - Supplies the address of the bridge response.
//
// Return Value:
//
//    X0 after the BRK instruction.
//
//--

    .globl BRIDGE_SYMBOL(bridge_brk)
BRIDGE_SYMBOL(bridge_brk):

//
// X9 is a temporary register, which the caller does not expect to keep. It
// holds the address of the response structure across the BRK instruction.
//

    mov     x9, x1

//
// Assign the packet values to the registers. The request and the method are
// adjacent 16-bit fields, so one 32-bit load reads both.
//

    ldp     x2, x3, [x0, #BRIDGE_PACKET_VALUE1]
    ldp     x4, x5, [x0, #BRIDGE_PACKET_VALUE3]
    ldr     w1, [x0, #BRIDGE_PACKET_REQUEST]
    ldr     w0, [x0, #BRIDGE_PACKET_MAGIC]

//
// Execute the BRK instruction.
//

    brk     #BRIDGE_BREAKPOINT_COMMENT

    cbz     x9, 1f

//
// Assign the response values to the response structure.
//

    stp     x0, x1, [x9, #BRIDGE_RESPONSE_VALUE1]
    stp     x2, x3, [x9, #BRIDGE_RESPONSE_VALUE3]

1:
    ret
