/// A Windows page protection.
///
/// The value holds a base protection and at most one of the modifiers
/// `PAGE_GUARD`, `PAGE_NOCACHE` and `PAGE_WRITECOMBINE`. `VirtualAlloc` and
/// `VirtualProtect` take it.
///
/// # Implementation Details
///
/// The constants carry the names of the `PAGE_*` values.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowsPageProtection(u32);

impl WindowsPageProtection {
    /// Corresponds to `PAGE_NOACCESS`.
    pub const NOACCESS: Self = Self(0x01);

    /// Corresponds to `PAGE_READONLY`.
    pub const READONLY: Self = Self(0x02);

    /// Corresponds to `PAGE_READWRITE`.
    pub const READWRITE: Self = Self(0x04);

    /// Corresponds to `PAGE_WRITECOPY`.
    pub const WRITECOPY: Self = Self(0x08);

    /// Corresponds to `PAGE_EXECUTE`.
    pub const EXECUTE: Self = Self(0x10);

    /// Corresponds to `PAGE_EXECUTE_READ`.
    pub const EXECUTE_READ: Self = Self(0x20);

    /// Corresponds to `PAGE_EXECUTE_READWRITE`.
    pub const EXECUTE_READWRITE: Self = Self(0x40);

    /// Corresponds to `PAGE_EXECUTE_WRITECOPY`.
    pub const EXECUTE_WRITECOPY: Self = Self(0x80);

    /// Corresponds to `PAGE_GUARD`.
    pub const GUARD: Self = Self(0x100);

    /// Corresponds to `PAGE_NOCACHE`.
    pub const NOCACHE: Self = Self(0x200);

    /// Corresponds to `PAGE_WRITECOMBINE`.
    pub const WRITECOMBINE: Self = Self(0x400);
}

impl From<u32> for WindowsPageProtection {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<WindowsPageProtection> for u32 {
    fn from(value: WindowsPageProtection) -> Self {
        value.0
    }
}

impl std::ops::BitOr for WindowsPageProtection {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::fmt::Debug for WindowsPageProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "WindowsPageProtection({:#x})", self.0)
    }
}
