/// Bridge packet.
#[derive(Debug, Default)]
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
    /// Create a new packet with the given request and method.
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

    /// Set the first value of the packet.
    pub fn with_value1(self, value1: u64) -> Self {
        Self { value1, ..self }
    }

    /// Set the second value of the packet.
    pub fn with_value2(self, value2: u64) -> Self {
        Self { value2, ..self }
    }

    /// Set the third value of the packet.
    pub fn with_value3(self, value3: u64) -> Self {
        Self { value3, ..self }
    }

    /// Set the fourth value of the packet.
    pub fn with_value4(self, value4: u64) -> Self {
        Self { value4, ..self }
    }

    /// Get the magic number of the packet.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Get the request of the packet.
    pub fn request(&self) -> u16 {
        self.request
    }

    /// Get the method of the packet.
    pub fn method(&self) -> u16 {
        self.method
    }

    /// Get the first value of the packet.
    pub fn value1(&self) -> u64 {
        self.value1
    }

    /// Get the second value of the packet.
    pub fn value2(&self) -> u64 {
        self.value2
    }

    /// Get the third value of the packet.
    pub fn value3(&self) -> u64 {
        self.value3
    }

    /// Get the fourth value of the packet.
    pub fn value4(&self) -> u64 {
        self.value4
    }
}
