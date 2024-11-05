/// `DR2` debug register.
///
/// Contains the linear address of the third local breakpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Dr2(pub u64);

impl From<u64> for Dr2 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Dr2> for u64 {
    fn from(value: Dr2) -> Self {
        value.0
    }
}
