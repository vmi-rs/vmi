use serde::{Deserialize, Serialize};

use super::macros::impl_ops;
use crate::AddressContext;

impl_ops!(Gfn, u64, "Guest Frame Number");
impl_ops!(Pa, u64, "Guest Physical Address");
impl_ops!(Va, u64, "Guest Virtual Address");

impl Va {
    /// Checks if the virtual address is NULL.
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// The mechanism used for translating virtual addresses to physical addresses.
///
/// Understanding and navigating the memory translation mechanisms of the target
/// system is crucial. This enum allows specifying whether a direct mapping or a
/// paging-based translation should be used for memory accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TranslationMechanism {
    /// Direct mapping (no translation).
    ///
    /// In this mode, the provided address is treated as a physical address.
    /// This is useful for accessing physical memory directly.
    Direct,

    /// Paging-based translation.
    ///
    /// This mode uses the paging structures of the target system to translate
    /// virtual addresses to physical addresses. It's the common mode for
    /// accessing memory in most modern operating systems.
    Paging {
        /// Optionally specifies the root of the paging structure (e.g., CR3
        /// value in x86 architecture). If `None`, the current active
        /// paging structure of the target system should be used.
        root: Option<Pa>,
    },
}

/// Defines the context for memory access operations in VMI.
///
/// This struct encapsulates the necessary information to perform a memory
/// access, including the target address and the mechanism to use for address
/// translation. It's typically used in conjunction with memory read or write
/// operations in a VMI tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccessContext {
    /// The address to access.
    ///
    /// Depending on the [`mechanism`] field, this could be interpreted
    /// as either a virtual address or a physical address.
    ///
    /// [`mechanism`]: Self::mechanism
    pub address: u64,

    /// The mechanism used for address translation.
    ///
    /// This field determines how the [`address`] should be interpreted and
    /// processed during the memory access operation. It allows for
    /// flexibility in handling different memory layouts and translation
    /// schemes in the target system.
    ///
    /// [`address`]: Self::address
    pub mechanism: TranslationMechanism,
}

impl AccessContext {
    /// Creates a new `AccessContext` with direct mapping.
    pub fn direct(address: impl Into<Pa>) -> Self {
        Self {
            address: u64::from(address.into()),
            mechanism: TranslationMechanism::Direct,
        }
    }

    /// Creates a new `AccessContext` with paging-based translation.
    pub fn paging(address: impl Into<Va>, root: impl Into<Pa>) -> Self {
        Self {
            address: address.into().0,
            mechanism: TranslationMechanism::Paging {
                root: Some(root.into()),
            },
        }
    }
}

impl From<Pa> for AccessContext {
    fn from(value: Pa) -> Self {
        Self::direct(value)
    }
}

impl From<(Va, Pa)> for AccessContext {
    fn from(value: (Va, Pa)) -> Self {
        Self::paging(value.0, value.1)
    }
}

impl From<AddressContext> for AccessContext {
    fn from(value: AddressContext) -> Self {
        Self::paging(value.va, value.root)
    }
}

impl ::std::ops::Add<u64> for AccessContext {
    type Output = AccessContext;

    fn add(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address + rhs,
            ..self
        }
    }
}

impl ::std::ops::Add<AccessContext> for AccessContext {
    type Output = AccessContext;

    fn add(self, rhs: AccessContext) -> Self::Output {
        Self {
            address: self.address + rhs.address,
            ..self
        }
    }
}

impl ::std::ops::AddAssign<u64> for AccessContext {
    fn add_assign(&mut self, rhs: u64) {
        self.address += rhs;
    }
}

impl ::std::ops::AddAssign<AccessContext> for AccessContext {
    fn add_assign(&mut self, rhs: AccessContext) {
        self.address += rhs.address;
    }
}

impl ::std::ops::Sub<u64> for AccessContext {
    type Output = AccessContext;

    fn sub(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address - rhs,
            ..self
        }
    }
}

impl ::std::ops::Sub<AccessContext> for AccessContext {
    type Output = AccessContext;

    fn sub(self, rhs: AccessContext) -> Self::Output {
        Self {
            address: self.address - rhs.address,
            ..self
        }
    }
}

impl ::std::ops::SubAssign<u64> for AccessContext {
    fn sub_assign(&mut self, rhs: u64) {
        self.address -= rhs;
    }
}

impl ::std::ops::SubAssign<AccessContext> for AccessContext {
    fn sub_assign(&mut self, rhs: AccessContext) {
        self.address -= rhs.address;
    }
}

impl ::std::ops::Mul<u64> for AccessContext {
    type Output = AccessContext;

    fn mul(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address * rhs,
            ..self
        }
    }
}

impl ::std::ops::Mul<AccessContext> for AccessContext {
    type Output = AccessContext;

    fn mul(self, rhs: AccessContext) -> Self::Output {
        Self {
            address: self.address * rhs.address,
            ..self
        }
    }
}

impl ::std::ops::MulAssign<u64> for AccessContext {
    fn mul_assign(&mut self, rhs: u64) {
        self.address *= rhs;
    }
}

impl ::std::ops::MulAssign<AccessContext> for AccessContext {
    fn mul_assign(&mut self, rhs: AccessContext) {
        self.address *= rhs.address;
    }
}

impl ::std::ops::Div<u64> for AccessContext {
    type Output = AccessContext;

    fn div(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address / rhs,
            ..self
        }
    }
}

impl ::std::ops::Div<AccessContext> for AccessContext {
    type Output = AccessContext;

    fn div(self, rhs: AccessContext) -> Self::Output {
        Self {
            address: self.address / rhs.address,
            ..self
        }
    }
}

impl ::std::ops::DivAssign<u64> for AccessContext {
    fn div_assign(&mut self, rhs: u64) {
        self.address /= rhs;
    }
}

impl ::std::ops::DivAssign<AccessContext> for AccessContext {
    fn div_assign(&mut self, rhs: AccessContext) {
        self.address /= rhs.address;
    }
}

impl ::std::ops::BitAnd<u64> for AccessContext {
    type Output = AccessContext;

    fn bitand(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address & rhs,
            ..self
        }
    }
}

impl ::std::ops::BitAndAssign<u64> for AccessContext {
    fn bitand_assign(&mut self, rhs: u64) {
        self.address &= rhs;
    }
}

impl ::std::ops::BitOr<u64> for AccessContext {
    type Output = AccessContext;

    fn bitor(self, rhs: u64) -> Self::Output {
        Self {
            address: self.address | rhs,
            ..self
        }
    }
}

impl ::std::ops::BitOrAssign<u64> for AccessContext {
    fn bitor_assign(&mut self, rhs: u64) {
        self.address |= rhs;
    }
}
