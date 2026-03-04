use vmi_core::{VmiContext, VmiOs};

use super::ArchAdapter;

/// An incoming bridge request read from guest registers.
///
/// A packet carries the routing information (magic, request, method) and
/// up to four payload values. It is constructed by [`ArchAdapter::read_packet`]
/// from the VMI event's register state.
///
/// - `magic` identifies the bridge protocol (matched against
///   [`BridgeContract::MAGIC`](super::BridgeContract::MAGIC)).
/// - `request` selects the [`BridgeHandler`](super::BridgeHandler).
/// - `method` selects a sub-operation within the handler.
/// - `value1`-`value4` carry handler-specific payload.
///
/// # Architecture-specific
///
/// See the [`arch::amd64`](super::arch) module for the register-to-field
/// mapping on AMD64.
#[derive(Debug, Default, Clone, Copy)]
pub struct BridgePacket {
    magic: u32,
    request: u16,
    method: u16,
    value1: u64,
    value2: u64,
    value3: u64,
    value4: u64,
}

impl BridgePacket {
    /// Creates a new packet with the given magic, request and method.
    pub fn new(magic: u32, request: u16, method: u16) -> Self {
        Self {
            magic,
            request,
            method,
            value1: 0,
            value2: 0,
            value3: 0,
            value4: 0,
        }
    }

    /// Sets the first payload value.
    pub fn with_value1(self, value1: u64) -> Self {
        Self { value1, ..self }
    }

    /// Sets the second payload value.
    pub fn with_value2(self, value2: u64) -> Self {
        Self { value2, ..self }
    }

    /// Sets the third payload value.
    pub fn with_value3(self, value3: u64) -> Self {
        Self { value3, ..self }
    }

    /// Sets the fourth payload value.
    pub fn with_value4(self, value4: u64) -> Self {
        Self { value4, ..self }
    }

    /// Returns the magic number, identifying the bridge protocol.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Returns the request code, selecting the handler.
    pub fn request(&self) -> u16 {
        self.request
    }

    /// Returns the method code, selecting a sub-operation within the handler.
    pub fn method(&self) -> u16 {
        self.method
    }

    /// Returns the first payload value.
    pub fn value1(&self) -> u64 {
        self.value1
    }

    /// Returns the second payload value.
    pub fn value2(&self) -> u64 {
        self.value2
    }

    /// Returns the third payload value.
    pub fn value3(&self) -> u64 {
        self.value3
    }

    /// Returns the fourth payload value.
    pub fn value4(&self) -> u64 {
        self.value4
    }
}

/// Reads a [`BridgePacket`] from the VMI event's registers.
impl<Os> From<&VmiContext<'_, Os>> for BridgePacket
where
    Os: VmiOs,
    Os::Architecture: ArchAdapter,
{
    fn from(value: &VmiContext<'_, Os>) -> Self {
        Os::Architecture::read_packet(value.event())
    }
}
