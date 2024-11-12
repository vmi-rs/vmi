use serde::{Deserialize, Serialize};

use super::{Pa, Va};

/// A complete address context within a system for virtual to physical address
/// translation.
///
/// In virtual machine introspection (VMI) and memory analysis, it's often
/// necessary to work with addresses from different processes or memory spaces.
/// The `AddressContext` struct encapsulates both a virtual address and the
/// corresponding translation root, providing all the information needed to
/// accurately translate the virtual address to a physical address.
///
/// The `AddressContext` is commonly used as an input to memory access or
/// translation functions in VMI tools, ensuring that the correct translation
/// context is applied for each memory operation.
///
/// # Example
///
/// ```no_run
/// # use vmi_core::{AddressContext, Pa, Va};
/// let user_space_address = AddressContext {
///     va: Va(0x7ffe0000),
///     root: Pa(0x1000000),  // CR3 value for a specific process
/// };
///
/// let kernel_space_address = AddressContext {
///     va: Va(0xfffff80000000000),
///     root: Pa(0x2000000),  // CR3 value for kernel space
/// };
///
/// // These contexts can then be used in memory operations
/// // vmi.read(user_space_address, &mut buffer)?;
/// // vmi.translate_address(kernel_space_address)?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AddressContext {
    /// The virtual address.
    pub va: Va,

    /// The translation root, typically the base of the page table hierarchy
    /// (e.g., CR3 in x86).
    pub root: Pa,
}

impl AddressContext {
    /// Creates a new `AddressContext` with the given virtual address and
    /// translation root.
    pub fn new(va: impl Into<Va>, root: impl Into<Pa>) -> Self {
        Self {
            va: va.into(),
            root: root.into(),
        }
    }
}

//impl From<Va> for AddressContext {
//    fn from(value: Va) -> Self {
//        Self {
//            va: value,
//            root: None,
//        }
//    }
//}

impl From<(Va, Pa)> for AddressContext {
    fn from(value: (Va, Pa)) -> Self {
        Self {
            va: value.0,
            root: value.1,
        }
    }
}

impl ::std::ops::Add<u64> for AddressContext {
    type Output = AddressContext;

    fn add(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va + rhs,
            ..self
        }
    }
}

impl ::std::ops::Add<AddressContext> for AddressContext {
    type Output = AddressContext;

    fn add(self, rhs: AddressContext) -> Self::Output {
        Self {
            va: self.va + rhs.va,
            ..self
        }
    }
}

impl ::std::ops::AddAssign<u64> for AddressContext {
    fn add_assign(&mut self, rhs: u64) {
        self.va += rhs;
    }
}

impl ::std::ops::AddAssign<AddressContext> for AddressContext {
    fn add_assign(&mut self, rhs: AddressContext) {
        self.va += rhs.va;
    }
}

impl ::std::ops::Sub<u64> for AddressContext {
    type Output = AddressContext;

    fn sub(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va - rhs,
            ..self
        }
    }
}

impl ::std::ops::Sub<AddressContext> for AddressContext {
    type Output = AddressContext;

    fn sub(self, rhs: AddressContext) -> Self::Output {
        Self {
            va: self.va - rhs.va,
            ..self
        }
    }
}

impl ::std::ops::SubAssign<u64> for AddressContext {
    fn sub_assign(&mut self, rhs: u64) {
        self.va -= rhs;
    }
}

impl ::std::ops::SubAssign<AddressContext> for AddressContext {
    fn sub_assign(&mut self, rhs: AddressContext) {
        self.va -= rhs.va;
    }
}

impl ::std::ops::Mul<u64> for AddressContext {
    type Output = AddressContext;

    fn mul(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va * rhs,
            ..self
        }
    }
}

impl ::std::ops::Mul<AddressContext> for AddressContext {
    type Output = AddressContext;

    fn mul(self, rhs: AddressContext) -> Self::Output {
        Self {
            va: self.va * rhs.va,
            ..self
        }
    }
}

impl ::std::ops::MulAssign<u64> for AddressContext {
    fn mul_assign(&mut self, rhs: u64) {
        self.va *= rhs;
    }
}

impl ::std::ops::MulAssign<AddressContext> for AddressContext {
    fn mul_assign(&mut self, rhs: AddressContext) {
        self.va *= rhs.va;
    }
}

impl ::std::ops::Div<u64> for AddressContext {
    type Output = AddressContext;

    fn div(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va / rhs,
            ..self
        }
    }
}

impl ::std::ops::Div<AddressContext> for AddressContext {
    type Output = AddressContext;

    fn div(self, rhs: AddressContext) -> Self::Output {
        Self {
            va: self.va / rhs.va,
            ..self
        }
    }
}

impl ::std::ops::DivAssign<u64> for AddressContext {
    fn div_assign(&mut self, rhs: u64) {
        self.va /= rhs;
    }
}

impl ::std::ops::DivAssign<AddressContext> for AddressContext {
    fn div_assign(&mut self, rhs: AddressContext) {
        self.va /= rhs.va;
    }
}

impl ::std::ops::BitAnd<u64> for AddressContext {
    type Output = AddressContext;

    fn bitand(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va & rhs,
            ..self
        }
    }
}

impl ::std::ops::BitAndAssign<u64> for AddressContext {
    fn bitand_assign(&mut self, rhs: u64) {
        self.va &= rhs;
    }
}

impl ::std::ops::BitOr<u64> for AddressContext {
    type Output = AddressContext;

    fn bitor(self, rhs: u64) -> Self::Output {
        Self {
            va: self.va | rhs,
            ..self
        }
    }
}

impl ::std::ops::BitOrAssign<u64> for AddressContext {
    fn bitor_assign(&mut self, rhs: u64) {
        self.va |= rhs;
    }
}

impl ::std::fmt::Display for AddressContext {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{} @ {}", self.va, self.root)
    }
}
