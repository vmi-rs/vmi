/// `DR1` debug register.
///
/// Contains the linear address of the second local breakpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr1(pub u64);

impl From<u64> for Dr1 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr1> for u64 {
    fn from(value: Dr1) -> Self {
        value.0
    }
}
