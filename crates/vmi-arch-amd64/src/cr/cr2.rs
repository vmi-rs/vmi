use vmi_core::Va;

/// `CR2` control register.
///
/// Contains the linear address that caused a page fault.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cr2(pub u64);

impl From<u64> for Cr2 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Cr2> for u64 {
    fn from(value: Cr2) -> Self {
        value.0
    }
}

impl From<Va> for Cr2 {
    fn from(value: Va) -> Self {
        Self(value.into())
    }
}

impl From<Cr2> for Va {
    fn from(value: Cr2) -> Self {
        value.0.into()
    }
}
