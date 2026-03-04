//! Architecture-specific adapters for reading bridge packets from VMI
//! events and writing responses back into guest registers.

mod amd64;

use vmi_core::{Architecture, VmiEvent, arch::GpRegisters};

use super::BridgePacket;

/// Architecture-specific adapter for the bridge protocol.
///
/// Converts VMI events into [`BridgePacket`]s by extracting register values
/// according to the architecture's calling convention.
pub trait ArchAdapter: Architecture + Sized + 'static {
    /// Reads a [`BridgePacket`] from a VMI event's registers.
    ///
    /// # Architecture-specific
    ///
    /// - **AMD64 (x64, VMCALL)**: magic from `RCX`, request+method from
    ///   `RDX`, values from `R8`-`R11`.
    /// - **AMD64 (x86, VMCALL)**: magic from `EBP`, request+method from
    ///   `EDX`, only 2 value slots (`ESI`, `EDI`) due to the Xen
    ///   hypercall ABI consuming `EAX`, `EBX`, `ECX`.
    /// - **AMD64 (x64, CPUID)**: magic from `leaf` (EAX), request+method from
    ///   `subleaf` (ECX), values from `R8`-`R11`.
    /// - **AMD64 (x86, CPUID)**: magic from `leaf` (EAX), request+method from
    ///   `subleaf` (ECX), values from `EBX`, `EDX`, `ESI`, `EDI`.
    ///
    /// See the [`amd64`] module docs for the full register layout.
    fn read_packet(event: &VmiEvent<Self>) -> BridgePacket;
}

/// Adapter for writing bridge response values back into general-purpose
/// registers.
///
/// Each architecture maps the four response values to specific registers.
///
/// # Architecture-specific
///
/// **AMD64**: `RAX`, `RBX`, `RCX` and `RDX`.
pub trait GpRegistersAdapter: GpRegisters + Sized + 'static {
    /// Writes response values into the register set.
    ///
    /// `None` values leave the corresponding register unchanged.
    fn write_response(
        &mut self,
        value1: Option<u64>,
        value2: Option<u64>,
        value3: Option<u64>,
        value4: Option<u64>,
    );
}
