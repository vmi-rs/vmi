use vmi_core::MemoryAccess;

use super::WindowsPageProtection;

/// Corresponds to `MM_PROTECTION_OPERATION_MASK`. It selects the base
/// protection, without the modifiers.
const MM_PROTECTION_OPERATION_MASK: u8 = 0x07;

/// A protection of the Windows memory manager.
///
/// The memory manager keeps the protection of a page as a 5-bit value, in a
/// VAD and in an invalid PTE. The low three bits select the base protection.
/// The upper two select a modifier (no-cache, guard page or write-combine).
/// A modifier on the base protection `MM_ZERO_ACCESS` means no access.
///
/// # Implementation Details
///
/// The memory manager calls the value a protection mask and gives it no
/// type. The constants carry the names of its `MM_*` values.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowsMmProtection(u8);

impl WindowsMmProtection {
    /// Corresponds to `MM_ZERO_ACCESS`.
    pub const ZERO_ACCESS: Self = Self(0);

    /// Corresponds to `MM_READONLY`.
    pub const READONLY: Self = Self(1);

    /// Corresponds to `MM_EXECUTE`.
    pub const EXECUTE: Self = Self(2);

    /// Corresponds to `MM_EXECUTE_READ`.
    pub const EXECUTE_READ: Self = Self(3);

    /// Corresponds to `MM_READWRITE`.
    pub const READWRITE: Self = Self(4);

    /// Corresponds to `MM_WRITECOPY`.
    pub const WRITECOPY: Self = Self(5);

    /// Corresponds to `MM_EXECUTE_READWRITE`.
    pub const EXECUTE_READWRITE: Self = Self(6);

    /// Corresponds to `MM_EXECUTE_WRITECOPY`.
    pub const EXECUTE_WRITECOPY: Self = Self(7);

    /// Corresponds to `MM_NOCACHE`.
    pub const NOCACHE: Self = Self(0x08);

    /// Corresponds to `MM_GUARD_PAGE`.
    pub const GUARD_PAGE: Self = Self(0x10);

    /// Corresponds to `MM_WRITECOMBINE`.
    pub const WRITECOMBINE: Self = Self(0x18);

    /// Corresponds to `MM_DECOMMIT`, which is `MM_GUARD_PAGE` on
    /// `MM_ZERO_ACCESS`.
    pub const DECOMMIT: Self = Self(0x10);

    /// Corresponds to `MM_NOACCESS`, which is `MM_WRITECOMBINE` on
    /// `MM_ZERO_ACCESS`.
    pub const NOACCESS: Self = Self(0x18);

    /// Returns the base protection, from `MM_ZERO_ACCESS` to
    /// `MM_EXECUTE_WRITECOPY`.
    pub fn base(self) -> Self {
        Self(self.0 & MM_PROTECTION_OPERATION_MASK)
    }

    /// Returns the modifier, which is `MM_NOCACHE`, `MM_GUARD_PAGE`,
    /// `MM_WRITECOMBINE` or none.
    pub fn modifier(self) -> Self {
        Self(self.0 & (Self::NOCACHE | Self::GUARD_PAGE).0)
    }

    /// Returns `true` for a guard page.
    ///
    /// A guard page carries `MM_GUARD_PAGE` on a base protection other than
    /// `MM_ZERO_ACCESS`. The first access to a guard page clears its guard
    /// bit and raises `STATUS_GUARD_PAGE_VIOLATION` in the thread.
    pub fn is_guard_page(self) -> bool {
        self.modifier() == Self::GUARD_PAGE && self.base() != Self::ZERO_ACCESS
    }

    /// Returns `true` for a no-access page.
    ///
    /// A no-access page carries a modifier on `MM_ZERO_ACCESS`, such as
    /// `MM_DECOMMIT` and `MM_NOACCESS`. An access to it raises an access
    /// violation. `MM_ZERO_ACCESS` alone does not mark a no-access page. A
    /// PTE that is zero carries it, and the VAD then decides the protection
    /// of the page.
    pub fn is_no_access(self) -> bool {
        self.base() == Self::ZERO_ACCESS && self != Self::ZERO_ACCESS
    }

    /// Returns the page protection of the Windows API, as the kernel's
    /// `MmProtectToValue` table gives it.
    pub fn page_protection(self) -> WindowsPageProtection {
        let base = match self.base() {
            Self::READONLY => WindowsPageProtection::READONLY,
            Self::EXECUTE => WindowsPageProtection::EXECUTE,
            Self::EXECUTE_READ => WindowsPageProtection::EXECUTE_READ,
            Self::READWRITE => WindowsPageProtection::READWRITE,
            Self::WRITECOPY => WindowsPageProtection::WRITECOPY,
            Self::EXECUTE_READWRITE => WindowsPageProtection::EXECUTE_READWRITE,
            Self::EXECUTE_WRITECOPY => WindowsPageProtection::EXECUTE_WRITECOPY,
            _ => return WindowsPageProtection::NOACCESS,
        };

        match self.modifier() {
            Self::NOCACHE => base | WindowsPageProtection::NOCACHE,
            Self::GUARD_PAGE => base | WindowsPageProtection::GUARD,
            Self::WRITECOMBINE => base | WindowsPageProtection::WRITECOMBINE,
            _ => base,
        }
    }

    /// Returns the access rights of the protection.
    ///
    /// Write-copy counts as writable. The modifiers do not change the rights.
    /// A guard page can still be read, written or run once its guard fault
    /// fires.
    pub fn memory_access(self) -> MemoryAccess {
        match self.base() {
            Self::READONLY => MemoryAccess::R,
            Self::EXECUTE => MemoryAccess::X,
            Self::EXECUTE_READ => MemoryAccess::RX,
            Self::READWRITE | Self::WRITECOPY => MemoryAccess::RW,
            Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY => MemoryAccess::RWX,
            _ => MemoryAccess::default(),
        }
    }
}

impl From<u8> for WindowsMmProtection {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<WindowsMmProtection> for u8 {
    fn from(value: WindowsMmProtection) -> Self {
        value.0
    }
}

impl std::ops::BitOr for WindowsMmProtection {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::fmt::Debug for WindowsMmProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "WindowsMmProtection({:#x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's `MmProtectToValue` table. It comes from the
    /// `ntoskrnl.exe` of builds 7601, 19045, 22631 and 26300, which all hold
    /// the same 32 entries.
    const MM_PROTECT_TO_VALUE: [u32; 32] = [
        0x001, 0x002, 0x010, 0x020, 0x004, 0x008, 0x040, 0x080, 0x001, 0x202, 0x210, 0x220, 0x204,
        0x208, 0x240, 0x280, 0x001, 0x102, 0x110, 0x120, 0x104, 0x108, 0x140, 0x180, 0x001, 0x402,
        0x410, 0x420, 0x404, 0x408, 0x440, 0x480,
    ];

    /// Checks the conversion against `MmProtectToValue`.
    #[test]
    fn page_protection_matches_the_kernel_table() {
        for (value, expected) in (0u8..).zip(MM_PROTECT_TO_VALUE) {
            assert_eq!(
                WindowsMmProtection::from(value).page_protection(),
                WindowsPageProtection::from(expected),
                "{value:#x}"
            );
        }
    }

    /// Checks guard pages and no-access pages against `MmProtectToValue`. A
    /// guard page maps to `PAGE_GUARD`, and a no-access page maps to
    /// `PAGE_NOACCESS`. `MM_ZERO_ACCESS` alone maps to `PAGE_NOACCESS` too,
    /// but it does not mark a no-access page.
    #[test]
    fn guard_and_no_access_pages_match_the_kernel_table() {
        for (value, page) in (0u8..).zip(MM_PROTECT_TO_VALUE) {
            let protection = WindowsMmProtection::from(value);
            assert_eq!(
                protection.is_guard_page(),
                page & u32::from(WindowsPageProtection::GUARD) != 0,
                "{value:#x}"
            );
            assert_eq!(
                protection.is_no_access(),
                value != 0 && page == u32::from(WindowsPageProtection::NOACCESS),
                "{value:#x}"
            );
        }
    }

    /// Checks that no-access values carry no rights and that the modifiers
    /// keep the base rights.
    #[test]
    fn memory_access_follows_the_base_protection() {
        for no_access in [
            WindowsMmProtection::ZERO_ACCESS,
            WindowsMmProtection::NOCACHE,
            WindowsMmProtection::DECOMMIT,
            WindowsMmProtection::NOACCESS,
        ] {
            assert_eq!(no_access.memory_access(), MemoryAccess::default());
        }

        assert_eq!(
            (WindowsMmProtection::GUARD_PAGE | WindowsMmProtection::EXECUTE_READ).memory_access(),
            MemoryAccess::RX
        );
        assert_eq!(
            (WindowsMmProtection::NOCACHE | WindowsMmProtection::EXECUTE_WRITECOPY).memory_access(),
            MemoryAccess::RWX
        );
    }
}
