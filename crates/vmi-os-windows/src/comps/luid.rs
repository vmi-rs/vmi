/// A 64-bit locally-unique identifier.
///
/// # Implementation Details
///
/// Corresponds to `_LUID`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowsLuid(u64);

impl WindowsLuid {
    /// Constructs a LUID from its halves.
    pub const fn new(low_part: u32, high_part: i32) -> Self {
        Self(((high_part as u32 as u64) << 32) | (low_part as u64))
    }

    /// Returns the low 32 bits.
    pub const fn low_part(self) -> u32 {
        self.0 as u32
    }

    /// Returns the high 32 bits.
    pub const fn high_part(self) -> i32 {
        (self.0 >> 32) as i32
    }

    /// Returns the LUID as a single 64-bit value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for WindowsLuid {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for WindowsLuid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "({:x}, {:x})", self.high_part(), self.low_part())
    }
}
