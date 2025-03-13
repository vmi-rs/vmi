/// Bridge packet.
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
    /// Creates a new packet with the given request and method.
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

    /// Sets the first value of the packet.
    pub fn with_value1(self, value1: u64) -> Self {
        Self { value1, ..self }
    }

    /// Sets the second value of the packet.
    pub fn with_value2(self, value2: u64) -> Self {
        Self { value2, ..self }
    }

    /// Sets the third value of the packet.
    pub fn with_value3(self, value3: u64) -> Self {
        Self { value3, ..self }
    }

    /// Sets the fourth value of the packet.
    pub fn with_value4(self, value4: u64) -> Self {
        Self { value4, ..self }
    }

    /// Returns the magic number of the packet.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Returns the request of the packet.
    pub fn request(&self) -> u16 {
        self.request
    }

    /// Returns the method of the packet.
    pub fn method(&self) -> u16 {
        self.method
    }

    /// Returns the first value of the packet.
    pub fn value1(&self) -> u64 {
        self.value1
    }

    /// Returns the second value of the packet.
    pub fn value2(&self) -> u64 {
        self.value2
    }

    /// Returns the third value of the packet.
    pub fn value3(&self) -> u64 {
        self.value3
    }

    /// Returns the fourth value of the packet.
    pub fn value4(&self) -> u64 {
        self.value4
    }
}
