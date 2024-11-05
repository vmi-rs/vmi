use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// Memory access permission flags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MemoryAccess: u8 {
        /// Read permission.
        const R = 0b00000001;

        /// Write permission.
        const W = 0b00000010;

        /// Execute permission.
        const X = 0b00000100;

        /// Combined Read and Write permissions.
        const RW = Self::R.bits() | Self::W.bits();

        /// Combined Write and Execute permissions.
        const WX = Self::W.bits() | Self::X.bits();

        /// Combined Read and Execute permissions.
        const RX = Self::R.bits() | Self::X.bits();

        /// Full access: Read, Write, and Execute permissions.
        const RWX = Self::R.bits() | Self::W.bits() | Self::X.bits();
    }
}

impl std::fmt::Display for MemoryAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut result = [b'-'; 3];

        if self.contains(MemoryAccess::R) {
            result[0] = b'r';
        }
        if self.contains(MemoryAccess::W) {
            result[1] = b'w';
        }
        if self.contains(MemoryAccess::X) {
            result[2] = b'x';
        }

        // SAFETY: The `result` array is always valid UTF-8.
        f.write_str(unsafe { std::str::from_utf8_unchecked(&result) })
    }
}
