//! AMD64 bridge adapter.
//!
//! # Register layout
//!
//! The bridge supports two event sources: **VMCALL** (`Hypercall`) and
//! **CPUID**.
//!
//! ## VMCALL (`Hypercall`)
//!
//! VMCALL is the intended mechanism. On Xen, triggering a hypercall
//! requires the hypercall ABI registers to be set up:
//!
//! **x64:**
//! ```asm
//! mov     eax, 0x22       ; __HYPERVISOR_hvm_op
//! mov     edi, 0x18       ; HVMOP_guest_request_vm_event
//! xor     rsi, rsi        ; arg = NULL
//! vmcall
//! ```
//!
//! **x86:**
//! ```asm
//! mov     eax, 0x22       ; __HYPERVISOR_hvm_op
//! mov     ebx, 0x18       ; HVMOP_guest_request_vm_event
//! xor     ecx, ecx        ; arg = NULL
//! vmcall
//! ```
//!
//! These registers (`EAX`, `EDI`/`EBX`, `RSI`/`ECX`) are consumed by the
//! hypercall ABI and cannot carry bridge data.
//!
//! On **x64** this is not an issue - the remaining registers (`R8`–`R11`)
//! provide four payload slots, and `RCX`/`RDX` carry magic and
//! request+method:
//!
//! | Field           | Register |
//! |-----------------|----------|
//! | magic           | `RCX`    |
//! | request+method  | `RDX`    |
//! | value1          | `R8`     |
//! | value2          | `R9`     |
//! | value3          | `R10`    |
//! | value4          | `R11`    |
//!
//! On **x86** the situation is tighter: out of 8 GP registers, 3 are
//! consumed by the hypercall ABI and `ESP` cannot be repurposed (there
//! is nowhere to save/restore it). XMM registers are not part of the
//! `vm_event` struct and fetching them would require an extra hypercall.
//! This leaves 4 usable registers, 2 of which carry magic and
//! request+method, leaving only 2 payload slots:
//!
//! | Field           | Register |
//! |-----------------|----------|
//! | magic           | `EBP`    |
//! | request+method  | `EDX`    |
//! | value1          | `ESI`    |
//! | value2          | `EDI`    |
//!
//! ## CPUID (legacy)
//!
//! CPUID provides 4 values via `leaf`/`subleaf`/`EBX`/`EDX`, but it
//! abuses an instruction not designed for guest-host communication.
//! It is retained for backwards compatibility with x86 injectors.
//!
//! | Field           | Source                                               |
//! |-----------------|------------------------------------------------------|
//! | magic           | `leaf` (EAX)                                         |
//! | request+method  | `subleaf` (ECX)                                      |
//! | value1–value4   | `EBX`, `EDX`, `ESI`, `EDI` (x86) or `R8`–`R11` (x64) |

use vmi_arch_amd64::{Amd64, EventReason, GpRegisters};
use vmi_core::{Registers as _, VmiEvent};

use super::{super::BridgePacket, ArchAdapter, GpRegistersAdapter};

impl ArchAdapter for Amd64 {
    fn read_packet(event: &VmiEvent<Amd64>) -> BridgePacket {
        let registers = event.registers();

        match registers.effective_address_width() {
            // x86: limited register budget, see module docs.
            4 => {
                #[expect(clippy::wildcard_in_or_patterns)]
                match event.reason() {
                    EventReason::CpuId(cpuid) => BridgePacket::new(
                        cpuid.leaf,                      // eax
                        (cpuid.subleaf & 0xFFFF) as u16, // ecx (lower 16 bits)
                        (cpuid.subleaf >> 16) as u16,    // ecx (upper 16 bits)
                    )
                    .with_value1(registers.rbx & 0xFFFFFFFF)
                    .with_value2(registers.rdx & 0xFFFFFFFF)
                    .with_value3(registers.rsi & 0xFFFFFFFF)
                    .with_value4(registers.rdi & 0xFFFFFFFF),
                    EventReason::Hypercall(_) | _ => BridgePacket::new(
                        registers.rbp as u32,
                        (registers.rdx & 0xFFFF) as u16,
                        (registers.rdx >> 16) as u16,
                    )
                    .with_value1(registers.rsi & 0xFFFFFFFF)
                    .with_value2(registers.rdi & 0xFFFFFFFF),
                }
            }
            // x64: plenty of registers available.
            8 => {
                #[expect(clippy::wildcard_in_or_patterns)]
                let packet = match event.reason() {
                    EventReason::CpuId(cpuid) => BridgePacket::new(
                        cpuid.leaf,                      // eax
                        (cpuid.subleaf & 0xFFFF) as u16, // ecx (lower 16 bits)
                        (cpuid.subleaf >> 16) as u16,    // ecx (upper 16 bits)
                    ),
                    EventReason::Hypercall(_) | _ => BridgePacket::new(
                        registers.rcx as u32,
                        (registers.rdx & 0xFFFF) as u16,
                        (registers.rdx >> 16) as u16,
                    ),
                };

                packet
                    .with_value1(registers.r8)
                    .with_value2(registers.r9)
                    .with_value3(registers.r10)
                    .with_value4(registers.r11)
            }

            _ => panic!("Unsupported address width"),
        }
    }
}

/// Writes response values into AMD64 GP registers.
///
/// Maps value1–value4 to `RAX`, `RBX`, `RCX`, `RDX`.
impl GpRegistersAdapter for GpRegisters {
    fn write_response(
        &mut self,
        value1: Option<u64>,
        value2: Option<u64>,
        value3: Option<u64>,
        value4: Option<u64>,
    ) {
        if let Some(value) = value1 {
            self.rax = value;
        }
        if let Some(value) = value2 {
            self.rbx = value;
        }
        if let Some(value) = value3 {
            self.rcx = value;
        }
        if let Some(value) = value4 {
            self.rdx = value;
        }
    }
}
